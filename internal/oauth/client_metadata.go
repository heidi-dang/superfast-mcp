package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	dynamicClientPrefix = "urn:superfast:oauth-client:"
	maxCIMDBytes        = 32 * 1024
	maxCIMDCacheEntries = 256
	defaultCIMDCache    = 5 * time.Minute
	maxCIMDCache        = time.Hour
)

type ClientMetadata struct {
	ClientID                string
	ClientName              string
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	ApplicationType         string
}

type ClientRegistrationInput struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
}

type dynamicClientClaims struct {
	Type                    string   `json:"typ"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
	jwt.RegisteredClaims
}

type cimdDocument struct {
	ClientID                          string   `json:"client_id"`
	ClientName                        string   `json:"client_name"`
	RedirectURIs                      []string `json:"redirect_uris"`
	GrantTypes                        []string `json:"grant_types"`
	ResponseTypes                     []string `json:"response_types"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ApplicationType                   string   `json:"application_type"`
}

type clientMetadataInput struct {
	ClientID                          string
	ClientName                        string
	RedirectURIs                      []string
	GrantTypes                        []string
	ResponseTypes                     []string
	TokenEndpointAuthMethod           string
	TokenEndpointAuthMethodsSupported []string
	ApplicationType                   string
}

type cimdFetchResult struct {
	Status       int
	ContentType  string
	CacheControl string
	Body         []byte
}

type cimdCacheEntry struct {
	metadata  ClientMetadata
	expiresAt time.Time
}

type ClientResolver struct {
	issuer string
	secret []byte

	lookupIP      func(context.Context, string) ([]net.IPAddr, error)
	fetchDocument func(context.Context, string, net.IPAddr) (cimdFetchResult, error)
	now           func() time.Time

	mu    sync.Mutex
	cache map[string]cimdCacheEntry
}

func NewClientResolver(issuer string, secret []byte) *ClientResolver {
	resolver := &ClientResolver{
		issuer: strings.TrimRight(issuer, "/"),
		secret: append([]byte(nil), secret...),
		now:    time.Now,
		cache:  make(map[string]cimdCacheEntry),
	}
	resolver.lookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	resolver.fetchDocument = fetchPinnedCIMDDocument
	return resolver
}

func (r *ClientResolver) IssueDynamicClient(input ClientRegistrationInput) (string, ClientMetadata, int64, error) {
	metadata, err := normalizeResolvedClientMetadata(clientMetadataInput{
		ClientID:                "pending",
		ClientName:              input.ClientName,
		RedirectURIs:            input.RedirectURIs,
		GrantTypes:              input.GrantTypes,
		ResponseTypes:           input.ResponseTypes,
		TokenEndpointAuthMethod: input.TokenEndpointAuthMethod,
		ApplicationType:         input.ApplicationType,
	})
	if err != nil {
		return "", ClientMetadata{}, 0, err
	}
	issuedAt := r.now().Unix()
	claims := dynamicClientClaims{
		Type:                    "dcr-client",
		ClientName:              metadata.ClientName,
		RedirectURIs:            metadata.RedirectURIs,
		TokenEndpointAuthMethod: "none",
		ApplicationType:         metadata.ApplicationType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   r.issuer,
			Audience: jwt.ClaimStrings{r.issuer + "/oauth/register"},
			IssuedAt: jwt.NewNumericDate(time.Unix(issuedAt, 0)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(r.secret)
	if err != nil {
		return "", ClientMetadata{}, 0, fmt.Errorf("sign dynamic client metadata: %w", err)
	}
	clientID := dynamicClientPrefix + signed
	metadata.ClientID = clientID
	return clientID, metadata, issuedAt, nil
}

func (r *ClientResolver) Resolve(ctx context.Context, clientID string) (ClientMetadata, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return ClientMetadata{}, errors.New("unknown OAuth client_id")
	}
	if strings.HasPrefix(clientID, dynamicClientPrefix) {
		return r.resolveDynamicClient(clientID)
	}
	if u, err := url.Parse(clientID); err == nil && u.Scheme != "" {
		return r.resolveCIMD(ctx, clientID)
	}
	return ClientMetadata{}, errors.New("unknown OAuth client_id")
}

func (r *ClientResolver) resolveDynamicClient(clientID string) (ClientMetadata, error) {
	signed := strings.TrimPrefix(clientID, dynamicClientPrefix)
	if signed == "" {
		return ClientMetadata{}, errors.New("invalid dynamic client registration")
	}
	claims := &dynamicClientClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(r.issuer),
		jwt.WithAudience(r.issuer+"/oauth/register"),
	)
	token, err := parser.ParseWithClaims(signed, claims, func(*jwt.Token) (any, error) { return r.secret, nil })
	if err != nil || !token.Valid || claims.Type != "dcr-client" {
		return ClientMetadata{}, errors.New("invalid dynamic client registration")
	}
	return normalizeResolvedClientMetadata(clientMetadataInput{
		ClientID:                clientID,
		ClientName:              claims.ClientName,
		RedirectURIs:            claims.RedirectURIs,
		TokenEndpointAuthMethod: claims.TokenEndpointAuthMethod,
		ApplicationType:         claims.ApplicationType,
	})
}

func normalizeResolvedClientMetadata(input clientMetadataInput) (ClientMetadata, error) {
	clientName := strings.TrimSpace(input.ClientName)
	if clientName == "" || len(clientName) > 160 {
		return ClientMetadata{}, errors.New("client_name is required")
	}
	if len(input.RedirectURIs) == 0 || len(input.RedirectURIs) > 20 {
		return ClientMetadata{}, errors.New("redirect_uris is required")
	}
	seenRedirects := make(map[string]struct{}, len(input.RedirectURIs))
	redirects := make([]string, 0, len(input.RedirectURIs))
	for _, raw := range input.RedirectURIs {
		normalized, err := validateClientRedirectURI(raw)
		if err != nil {
			return ClientMetadata{}, err
		}
		if _, ok := seenRedirects[normalized]; ok {
			continue
		}
		seenRedirects[normalized] = struct{}{}
		redirects = append(redirects, normalized)
	}
	if len(input.GrantTypes) > 0 {
		hasCode := false
		for _, grant := range input.GrantTypes {
			switch grant {
			case "authorization_code":
				hasCode = true
			case "refresh_token":
			default:
				return ClientMetadata{}, fmt.Errorf("unsupported grant_type %q", grant)
			}
		}
		if !hasCode {
			return ClientMetadata{}, errors.New("authorization_code grant is required")
		}
	}
	if len(input.ResponseTypes) > 0 {
		if len(input.ResponseTypes) != 1 || input.ResponseTypes[0] != "code" {
			return ClientMetadata{}, errors.New("code response type is required")
		}
	}
	authMethod := strings.TrimSpace(input.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" {
		hasNone := false
		for _, method := range input.TokenEndpointAuthMethodsSupported {
			if method == "none" {
				hasNone = true
				break
			}
		}
		if !hasNone {
			return ClientMetadata{}, errors.New("only public clients using token_endpoint_auth_method=none are supported")
		}
		authMethod = "none"
	}
	applicationType := strings.TrimSpace(input.ApplicationType)
	if applicationType == "" {
		applicationType = "web"
	}
	if applicationType != "web" && applicationType != "native" {
		return ClientMetadata{}, errors.New("application_type must be web or native")
	}
	return ClientMetadata{
		ClientID:                input.ClientID,
		ClientName:              clientName,
		RedirectURIs:            redirects,
		TokenEndpointAuthMethod: authMethod,
		ApplicationType:         applicationType,
	}, nil
}

func validateClientRedirectURI(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("invalid redirect URI %q", raw)
	}
	if u.Scheme == "https" {
		return u.String(), nil
	}
	if u.Scheme == "http" && isLoopbackClientHost(u.Hostname()) {
		return u.String(), nil
	}
	return "", fmt.Errorf("redirect URI %q must use HTTPS or HTTP loopback", raw)
}

func isLoopbackClientHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (r *ClientResolver) resolveCIMD(ctx context.Context, clientID string) (ClientMetadata, error) {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Path == "" || u.Path == "/" {
		return ClientMetadata{}, errors.New("CIMD client_id must be an HTTPS URL with a path and no fragment or credentials")
	}
	if u.Port() != "" && u.Port() != "443" {
		return ClientMetadata{}, errors.New("CIMD client_id must use the default HTTPS port")
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return ClientMetadata{}, errors.New("CIMD client metadata host must be public")
	}

	r.mu.Lock()
	if entry, ok := r.cache[clientID]; ok && entry.expiresAt.After(r.now()) {
		metadata := entry.metadata
		r.mu.Unlock()
		return metadata, nil
	}
	r.mu.Unlock()

	addresses, err := r.lookupIP(ctx, u.Hostname())
	if err != nil || len(addresses) == 0 {
		return ClientMetadata{}, errors.New("CIMD client metadata host did not resolve")
	}
	for _, address := range addresses {
		if !isPublicCIMDAddress(address.IP) {
			return ClientMetadata{}, errors.New("client metadata host resolves to a non-public address")
		}
	}
	result, err := r.fetchDocument(ctx, clientID, addresses[0])
	if err != nil {
		return ClientMetadata{}, err
	}
	if result.Status != http.StatusOK {
		return ClientMetadata{}, errors.New("CIMD metadata request did not return 200")
	}
	if !strings.Contains(strings.ToLower(result.ContentType), "application/json") {
		return ClientMetadata{}, errors.New("CIMD metadata response must be JSON")
	}
	if len(result.Body) > maxCIMDBytes {
		return ClientMetadata{}, errors.New("CIMD metadata response is too large")
	}
	var document cimdDocument
	if err := json.Unmarshal(result.Body, &document); err != nil {
		return ClientMetadata{}, errors.New("CIMD metadata response is invalid JSON")
	}
	if document.ClientID != clientID {
		return ClientMetadata{}, errors.New("CIMD metadata client_id must exactly match its document URL")
	}
	metadata, err := normalizeResolvedClientMetadata(clientMetadataInput{
		ClientID:                          clientID,
		ClientName:                        document.ClientName,
		RedirectURIs:                      document.RedirectURIs,
		GrantTypes:                        document.GrantTypes,
		ResponseTypes:                     document.ResponseTypes,
		TokenEndpointAuthMethod:           document.TokenEndpointAuthMethod,
		TokenEndpointAuthMethodsSupported: document.TokenEndpointAuthMethodsSupported,
		ApplicationType:                   document.ApplicationType,
	})
	if err != nil {
		return ClientMetadata{}, err
	}
	cacheDuration := cimdCacheDuration(result.CacheControl)
	r.mu.Lock()
	if len(r.cache) >= maxCIMDCacheEntries {
		for key := range r.cache {
			delete(r.cache, key)
			break
		}
	}
	r.cache[clientID] = cimdCacheEntry{metadata: metadata, expiresAt: r.now().Add(cacheDuration)}
	r.mu.Unlock()
	return metadata, nil
}

func cimdCacheDuration(cacheControl string) time.Duration {
	for _, directive := range strings.Split(cacheControl, ",") {
		directive = strings.TrimSpace(strings.ToLower(directive))
		if !strings.HasPrefix(directive, "max-age=") {
			continue
		}
		seconds, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(directive, "max-age=")))
		if err != nil || seconds < 0 {
			break
		}
		duration := time.Duration(seconds) * time.Second
		if duration > maxCIMDCache {
			return maxCIMDCache
		}
		return duration
	}
	return defaultCIMDCache
}

var blockedCIMDPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("ff00::/8"),
}

func isPublicCIMDAddress(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range blockedCIMDPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func fetchPinnedCIMDDocument(ctx context.Context, clientID string, selected net.IPAddr) (cimdFetchResult, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return cimdFetchResult{}, err
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	selectedAddress := net.JoinHostPort(selected.IP.String(), "443")
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: u.Hostname(),
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, selectedAddress)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return cimdFetchResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return cimdFetchResult{}, fmt.Errorf("CIMD metadata request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxCIMDBytes {
		return cimdFetchResult{}, errors.New("CIMD metadata response is too large")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDBytes+1))
	if err != nil {
		return cimdFetchResult{}, fmt.Errorf("read CIMD metadata response: %w", err)
	}
	if len(body) > maxCIMDBytes {
		return cimdFetchResult{}, errors.New("CIMD metadata response is too large")
	}
	return cimdFetchResult{
		Status:       resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		CacheControl: resp.Header.Get("Cache-Control"),
		Body:         body,
	}, nil
}

func PKCES256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
