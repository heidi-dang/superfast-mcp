package access

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/heidi-dang/superfast-mcp/internal/config"
)

type Identity struct {
	Subject string
	Email   string
	Scope   string
}

type Verifier interface {
	Verify(context.Context, string) (Identity, error)
}

type accessClaims struct {
	Email    string `json:"email"`
	Scope    string `json:"scope"`
	Resource string `json:"resource,omitempty"`
	jwt.RegisteredClaims
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type JWTVerifier struct {
	cfg        config.CloudflareAccessConfig
	httpClient *http.Client
	parser     *jwt.Parser

	mu            sync.RWMutex
	keys          map[string]*rsa.PublicKey
	keysFetchedAt time.Time
}

func NewVerifier(cfg config.CloudflareAccessConfig, client *http.Client) (*JWTVerifier, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("access: jwks url is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	} else {
		boundedClient := *client
		if boundedClient.Timeout <= 0 || boundedClient.Timeout > 5*time.Second {
			boundedClient.Timeout = 5 * time.Second
		}
		client = &boundedClient
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)

	return &JWTVerifier{
		cfg:        cfg,
		httpClient: client,
		parser:     parser,
		keys:       make(map[string]*rsa.PublicKey),
	}, nil
}

func (v *JWTVerifier) Verify(ctx context.Context, assertion string) (Identity, error) {
	assertion = strings.TrimSpace(assertion)
	if assertion == "" {
		return Identity{}, errors.New("empty assertion")
	}

	var claims accessClaims
	token, err := v.parser.ParseWithClaims(assertion, &claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("missing kid in token header")
		}
		return v.getKey(ctx, kid)
	})
	if err != nil {
		return Identity{}, err
	}
	if !token.Valid {
		return Identity{}, errors.New("invalid token")
	}

	if !strings.EqualFold(claims.Email, v.cfg.AllowedEmail) {
		return Identity{}, errors.New("unauthorized email")
	}

	if claims.Subject == "" {
		return Identity{}, errors.New("empty subject")
	}

	if claims.Resource != "" && claims.Resource != v.cfg.Resource {
		return Identity{}, errors.New("resource mismatch")
	}

	tokenScopes := strings.Fields(claims.Scope)
	scopeSet := make(map[string]struct{}, len(tokenScopes))
	for _, s := range tokenScopes {
		scopeSet[s] = struct{}{}
	}
	for _, required := range v.cfg.RequiredScopes {
		if _, ok := scopeSet[required]; !ok {
			return Identity{}, fmt.Errorf("missing required scope: %s", required)
		}
	}

	return Identity{
		Subject: claims.Subject,
		Email:   claims.Email,
		Scope:   claims.Scope,
	}, nil
}

func (v *JWTVerifier) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	fresh := time.Since(v.keysFetchedAt) < 5*time.Minute
	v.mu.RUnlock()

	if ok && fresh {
		return key, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check under write lock
	key, ok = v.keys[kid]
	fresh = time.Since(v.keysFetchedAt) < 5*time.Minute
	if ok && fresh {
		return key, nil
	}

	if err := v.refreshKeysLocked(ctx); err != nil {
		return nil, err
	}

	key, ok = v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key with kid %q not found in jwks", kid)
	}
	return key, nil
}

func (v *JWTVerifier) refreshKeysLocked(ctx context.Context) error {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks responded with status %d", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, 256*1024+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return fmt.Errorf("failed to read jwks response: %w", err)
	}
	if len(body) > 256*1024 {
		return errors.New("jwks response exceeds 256 KiB")
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to decode jwks response: %w", err)
	}

	parsedKeys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Kid == "" || k.N == "" || k.E == "" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		parsedKeys[k.Kid] = pub
	}

	v.keys = parsedKeys
	v.keysFetchedAt = time.Now()
	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		nBytes, err = base64.URLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, fmt.Errorf("invalid modulus: %w", err)
		}
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		eBytes, err = base64.URLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, fmt.Errorf("invalid exponent: %w", err)
		}
	}

	n := new(big.Int).SetBytes(nBytes)
	if n.Sign() <= 0 {
		return nil, errors.New("invalid modulus")
	}

	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	if e == 0 {
		return nil, errors.New("invalid public exponent")
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
