package access

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/heidi-dang/superfast-mcp/internal/config"
)

type testJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type testJWKSResponse struct {
	Keys []testJWK `json:"keys"`
}

func generateRSAKey(t *testing.T) (*rsa.PrivateKey, testJWK, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	kid := "key-" + time.Now().Format("20060102150405.000000000")
	jwk := testJWK{
		Kty: "RSA",
		Kid: kid,
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
	}
	return privKey, jwk, kid
}

func makeToken(t *testing.T, privKey *rsa.PrivateKey, kid string, method jwt.SigningMethod, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func defaultTestConfig(jwksURL string) config.CloudflareAccessConfig {
	return config.CloudflareAccessConfig{
		Issuer:         "https://test.cloudflareaccess.com",
		Audience:       "aud-12345",
		AllowedEmail:   "owner@example.com",
		JWKSURL:        jwksURL,
		Resource:       "https://mcp.example.com/mcp",
		RequiredScopes: []string{"mcp"},
	}
}

func TestNewVerifierBoundsHTTPClientTimeout(t *testing.T) {
	cfg := defaultTestConfig("https://jwks.example.com/certs")
	provided := &http.Client{}

	verifier, err := NewVerifier(cfg, provided)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}
	if verifier.httpClient == provided {
		t.Fatal("NewVerifier should clone a provided client before bounding its timeout")
	}
	if verifier.httpClient.Timeout != 5*time.Second {
		t.Fatalf("HTTP client timeout = %v, want 5s", verifier.httpClient.Timeout)
	}
	if provided.Timeout != 0 {
		t.Fatalf("provided client timeout mutated to %v", provided.Timeout)
	}

	shortClient := &http.Client{Timeout: time.Second}
	verifier, err = NewVerifier(cfg, shortClient)
	if err != nil {
		t.Fatalf("NewVerifier with short timeout failed: %v", err)
	}
	if verifier.httpClient.Timeout != time.Second {
		t.Fatalf("short HTTP client timeout = %v, want 1s", verifier.httpClient.Timeout)
	}
}

func TestVerifierAcceptsValidAccessAssertion(t *testing.T) {
	privKey, jwk, kid := generateRSAKey(t)
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			http.Error(w, "invalid Accept", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	})
	srv := httptest.NewServer(jwksHandler)
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	cfg.AllowedEmail = "OWNER@EXAMPLE.COM" // test case-insensitive match

	claims := accessClaims{
		Email:    "owner@example.com",
		Scope:    "read mcp write",
		Resource: "https://mcp.example.com/mcp",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-user-42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	tok := makeToken(t, privKey, kid, jwt.SigningMethodRS256, claims)

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	identity, err := verifier.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if identity.Subject != "sub-user-42" {
		t.Errorf("expected Subject 'sub-user-42', got %q", identity.Subject)
	}
	if identity.Email != "owner@example.com" {
		t.Errorf("expected Email 'owner@example.com', got %q", identity.Email)
	}
	if identity.Scope != "read mcp write" {
		t.Errorf("expected Scope 'read mcp write', got %q", identity.Scope)
	}
}

func TestVerifierRejectsWrongIssuer(t *testing.T) {
	privKey, jwk, kid := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	claims := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "mcp",
		Resource: cfg.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://wrong-issuer.com",
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	tok := makeToken(t, privKey, kid, jwt.SigningMethodRS256, claims)

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	_, err = verifier.Verify(context.Background(), tok)
	if err == nil {
		t.Fatalf("expected error for wrong issuer, got nil")
	}
}

func TestVerifierRejectsWrongAudience(t *testing.T) {
	privKey, jwk, kid := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	claims := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "mcp",
		Resource: cfg.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{"wrong-aud"},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	tok := makeToken(t, privKey, kid, jwt.SigningMethodRS256, claims)

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	_, err = verifier.Verify(context.Background(), tok)
	if err == nil {
		t.Fatalf("expected error for wrong audience, got nil")
	}
}

func TestVerifierRejectsWrongEmail(t *testing.T) {
	privKey, jwk, kid := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	claims := accessClaims{
		Email:    "attacker@example.com",
		Scope:    "mcp",
		Resource: cfg.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	tok := makeToken(t, privKey, kid, jwt.SigningMethodRS256, claims)

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	_, err = verifier.Verify(context.Background(), tok)
	if err == nil {
		t.Fatalf("expected error for wrong email, got nil")
	}
}

func TestVerifierRejectsMissingScope(t *testing.T) {
	privKey, jwk, kid := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	claims := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "read write", // missing "mcp"
		Resource: cfg.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	tok := makeToken(t, privKey, kid, jwt.SigningMethodRS256, claims)

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	_, err = verifier.Verify(context.Background(), tok)
	if err == nil {
		t.Fatalf("expected error for missing required scope, got nil")
	}
}

func TestVerifierRejectsResourceMismatch(t *testing.T) {
	privKey, jwk, kid := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	claims := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "mcp",
		Resource: "https://attacker.example.com/mcp",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	tok := makeToken(t, privKey, kid, jwt.SigningMethodRS256, claims)

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	_, err = verifier.Verify(context.Background(), tok)
	if err == nil {
		t.Fatalf("expected error for resource mismatch, got nil")
	}
}

func TestVerifierAllowsMissingResourceClaim(t *testing.T) {
	privKey, jwk, kid := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	claims := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "mcp",
		Resource: "", // omitted / empty
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	tok := makeToken(t, privKey, kid, jwt.SigningMethodRS256, claims)

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	identity, err := verifier.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify failed unexpectedly for missing resource claim: %v", err)
	}
	if identity.Subject != "sub-1" {
		t.Errorf("expected Subject 'sub-1', got %q", identity.Subject)
	}
}

func TestVerifierRejectsExpiredAssertion(t *testing.T) {
	privKey, jwk, kid := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	claims := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "mcp",
		Resource: cfg.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)), // expired past 30s leeway
		},
	}

	tok := makeToken(t, privKey, kid, jwt.SigningMethodRS256, claims)

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	_, err = verifier.Verify(context.Background(), tok)
	if err == nil {
		t.Fatalf("expected error for expired token, got nil")
	}
}

func TestVerifierRejectsNonRS256(t *testing.T) {
	_, jwk, kid := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: []testJWK{jwk}})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	claims := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "mcp",
		Resource: cfg.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	// Sign with HS256 (symmetric) instead of RS256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = kid
	tok, err := token.SignedString([]byte("hmac-secret-key-too-short-or-valid"))
	if err != nil {
		t.Fatalf("failed to sign token with HS256: %v", err)
	}

	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	_, err = verifier.Verify(context.Background(), tok)
	if err == nil {
		t.Fatalf("expected error for non-RS256 token, got nil")
	}
}

func TestVerifierRefreshesJWKSOnUnknownKID(t *testing.T) {
	privKey1, jwk1, kid1 := generateRSAKey(t)
	privKey2, jwk2, kid2 := generateRSAKey(t)

	var fetchCount atomic.Int32
	var currentKeys atomic.Value
	currentKeys.Store([]testJWK{jwk1})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		keys := currentKeys.Load().([]testJWK)
		_ = json.NewEncoder(w).Encode(testJWKSResponse{Keys: keys})
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	verifier, err := NewVerifier(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	// First verify with key1
	claims1 := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "mcp",
		Resource: cfg.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	tok1 := makeToken(t, privKey1, kid1, jwt.SigningMethodRS256, claims1)

	id1, err := verifier.Verify(context.Background(), tok1)
	if err != nil {
		t.Fatalf("first Verify failed: %v", err)
	}
	if id1.Subject != "sub-1" {
		t.Fatalf("unexpected subject: %q", id1.Subject)
	}
	if fetchCount.Load() != 1 {
		t.Fatalf("expected 1 fetch, got %d", fetchCount.Load())
	}

	// Now rotate server keys to include key2
	currentKeys.Store([]testJWK{jwk1, jwk2})

	// Verify token signed with key2 (which is not yet in verifier's cache)
	claims2 := accessClaims{
		Email:    cfg.AllowedEmail,
		Scope:    "mcp",
		Resource: cfg.Resource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			Subject:   "sub-2",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	tok2 := makeToken(t, privKey2, kid2, jwt.SigningMethodRS256, claims2)

	id2, err := verifier.Verify(context.Background(), tok2)
	if err != nil {
		t.Fatalf("second Verify (after rotation) failed: %v", err)
	}
	if id2.Subject != "sub-2" {
		t.Fatalf("unexpected subject: %q", id2.Subject)
	}
	if fetchCount.Load() != 2 {
		t.Fatalf("expected 2 fetches (JWKS refreshed for unknown kid), got %d", fetchCount.Load())
	}
}
