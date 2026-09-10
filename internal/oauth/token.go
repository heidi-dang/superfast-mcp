package oauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenIdentity struct {
	Subject  string
	Email    string
	ClientID string
	Scope    string
}

type accessTokenClaims struct {
	TokenUse string `json:"token_use"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	Email    string `json:"email,omitempty"`
	jwt.RegisteredClaims
}

type TokenIssuer struct {
	issuer   string
	resource string
	secret   []byte
	now      func() time.Time
}

func NewTokenIssuer(issuer, resource string, secret []byte) (*TokenIssuer, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	resource = strings.TrimSpace(resource)
	if issuer == "" || resource == "" {
		return nil, errors.New("native OAuth issuer and resource are required")
	}
	if len(secret) < 32 {
		return nil, errors.New("native OAuth token secret must be at least 32 bytes")
	}
	return &TokenIssuer{
		issuer:   issuer,
		resource: resource,
		secret:   append([]byte(nil), secret...),
		now:      time.Now,
	}, nil
}

func (i *TokenIssuer) MintAccessToken(identity TokenIdentity, ttl time.Duration) (string, error) {
	if strings.TrimSpace(identity.Subject) == "" {
		return "", errors.New("native OAuth subject is required")
	}
	if strings.TrimSpace(identity.ClientID) == "" {
		return "", errors.New("native OAuth client identity is required")
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := i.now()
	claims := accessTokenClaims{
		TokenUse: "access",
		ClientID: identity.ClientID,
		Scope:    identity.Scope,
		Email:    identity.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Audience:  jwt.ClaimStrings{i.resource},
			Subject:   identity.Subject,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(i.secret)
	if err != nil {
		return "", fmt.Errorf("sign native OAuth access token: %w", err)
	}
	return signed, nil
}

func (i *TokenIssuer) VerifyAccessToken(token string) (TokenIdentity, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return TokenIdentity{}, errors.New("native OAuth access token is empty")
	}
	claims := &accessTokenClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(i.issuer),
		jwt.WithAudience(i.resource),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(i.now),
	)
	parsed, err := parser.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return i.secret, nil })
	if err != nil || !parsed.Valid {
		if err == nil {
			err = errors.New("invalid native OAuth access token")
		}
		return TokenIdentity{}, err
	}
	if claims.TokenUse != "access" {
		return TokenIdentity{}, errors.New("native OAuth token use is invalid")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return TokenIdentity{}, errors.New("native OAuth subject is missing")
	}
	if strings.TrimSpace(claims.ClientID) == "" {
		return TokenIdentity{}, errors.New("native OAuth client identity is missing")
	}
	return TokenIdentity{
		Subject:  claims.Subject,
		Email:    claims.Email,
		ClientID: claims.ClientID,
		Scope:    claims.Scope,
	}, nil
}
