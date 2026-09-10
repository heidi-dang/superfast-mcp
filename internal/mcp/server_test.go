package mcpx

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/heidi-dang/superfast-mcp/internal/access"
	"github.com/heidi-dang/superfast-mcp/internal/config"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{Roots: []string{t.TempDir()}, Version: "test", AuthToken: "secret"}
}

func TestHTTPHandlerRequiresAuthenticationForMCP(t *testing.T) {
	handler, err := NewHTTPHandler(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="superfast-mcp"` {
		t.Fatalf("bearer challenge = %q", got)
	}
}

func TestHTTPHandlerHidesNativeMetadataByDefault(t *testing.T) {
	cfg := nativeHTTPTestConfig(t)
	handler, err := newHTTPHandler(cfg, &fakeAccessVerifier{identity: access.Identity{Subject: "owner", Email: "owner@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })

	for _, path := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-authorization-server",
	} {
		metadataReq := httptest.NewRequest(http.MethodGet, path, nil)
		metadataRec := httptest.NewRecorder()
		handler.ServeHTTP(metadataRec, metadataReq)
		if metadataRec.Code != http.StatusNotFound {
			t.Fatalf("path %s status = %d, want 404; body=%s", path, metadataRec.Code, metadataRec.Body.String())
		}
	}

	registerReq := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{"redirect_uris":["https://chatgpt.example/callback"],"client_name":"ChatGPT","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"web"}`))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body=%s", registerRec.Code, registerRec.Body.String())
	}

	mcpReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	mcpRec := httptest.NewRecorder()
	handler.ServeHTTP(mcpRec, mcpReq)
	if mcpRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated MCP status = %d, want 401", mcpRec.Code)
	}
	challenge := mcpRec.Header().Get("WWW-Authenticate")
	if strings.Contains(challenge, "resource_metadata=") {
		t.Fatalf("OAuth challenge must not expose resource metadata with Access verifier: %q", challenge)
	}
}

func TestHTTPHandlerPublishesOAuthDiscovery(t *testing.T) {
	cfg := nativeHTTPTestConfig(t)
	cfg.NativeOAuth.AdvertiseNativeMetadata = true
	handler, err := newHTTPHandler(cfg, &fakeAccessVerifier{identity: access.Identity{Subject: "owner", Email: "owner@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })

	metadataReq := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
	metadataRec := httptest.NewRecorder()
	handler.ServeHTTP(metadataRec, metadataReq)
	if metadataRec.Code != http.StatusOK {
		t.Fatalf("protected resource metadata status = %d, want 200; body=%s", metadataRec.Code, metadataRec.Body.String())
	}
	metadataBody := metadataRec.Body.String()
	if !strings.Contains(metadataBody, `"resource":"https://superfast.example.com/mcp"`) ||
		!strings.Contains(metadataBody, `"authorization_servers":["https://superfast.example.com"]`) {
		t.Fatalf("unexpected protected resource metadata: %s", metadataBody)
	}

	authMetadataReq := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	authMetadataRec := httptest.NewRecorder()
	handler.ServeHTTP(authMetadataRec, authMetadataReq)
	if authMetadataRec.Code != http.StatusOK {
		t.Fatalf("authorization metadata status = %d, want 200; body=%s", authMetadataRec.Code, authMetadataRec.Body.String())
	}
	authMetadataBody := authMetadataRec.Body.String()
	for _, want := range []string{
		`"issuer":"https://superfast.example.com"`,
		`"authorization_endpoint":"https://superfast.example.com/oauth/authorize"`,
		`"token_endpoint":"https://superfast.example.com/oauth/token"`,
		`"registration_endpoint":"https://superfast.example.com/oauth/register"`,
		`"revocation_endpoint":"https://superfast.example.com/oauth/revoke"`,
		`"client_id_metadata_document_supported":true`,
		`"S256"`,
	} {
		if !strings.Contains(authMetadataBody, want) {
			t.Fatalf("authorization metadata missing %s: %s", want, authMetadataBody)
		}
	}
}

func TestBearerAuthAcceptsValidToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := bearerAuth("secret", next)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "bearer secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestHTTPHandlerAcceptsStaticBearerForMCP(t *testing.T) {
	handler, err := NewHTTPHandler(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	req := newToolsListRequest("/mcp")
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("static bearer MCP status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandlerAcceptsCloudflareAccessAssertionForMCP(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "access-key-1"
	jwks := struct {
		Keys []map[string]string `json:"keys"`
	}{Keys: []map[string]string{{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
	}}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			http.Error(w, "missing application/json Accept header", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	cfg := testConfig(t)
	cfg.PublicURL = "https://superfast.example.com"
	cfg.CloudflareAccess = &config.CloudflareAccessConfig{
		Issuer:         "https://team.cloudflareaccess.com",
		Audience:       "app-audience",
		AllowedEmail:   "owner@example.com",
		JWKSURL:        jwksServer.URL,
		Resource:       "https://superfast.example.com/mcp",
		RequiredScopes: []string{"mcp"},
	}
	handler, err := NewHTTPHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	claims := struct {
		Email    string `json:"email"`
		Scope    string `json:"scope"`
		Resource string `json:"resource,omitempty"`
		jwt.RegisteredClaims
	}{
		Email:    "owner@example.com",
		Scope:    "mcp",
		Resource: "https://superfast.example.com/mcp",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://team.cloudflareaccess.com",
			Audience:  jwt.ClaimStrings{"app-audience"},
			Subject:   "owner-subject",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	assertion, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	req := newToolsListRequest("/mcp")
	req.Header.Set("Cf-Access-Jwt-Assertion", assertion)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Access-authenticated MCP status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func newToolsListRequest(path string) *http.Request {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"auth-test","version":"1"}}}}`
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/list")
	return req
}

func TestHealthIsPublicAndDoesNotLeakRoots(t *testing.T) {
	cfg := testConfig(t)
	handler, err := NewHTTPHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), cfg.Roots[0]) || !strings.Contains(rec.Body.String(), `"version":"test"`) {
		t.Fatalf("unexpected health body: %s", rec.Body.String())
	}
}

func TestHTTPHandlerFailsClosedWithoutAuth(t *testing.T) {
	cfg := testConfig(t)
	cfg.AuthToken = ""
	if _, err := NewHTTPHandler(cfg); err == nil {
		t.Fatal("expected unauthenticated handler construction to fail")
	}
	cfg.AllowUnauthenticatedHTTP = true
	if _, err := NewHTTPHandler(cfg); err != nil {
		t.Fatalf("explicit unauthenticated mode should be allowed: %v", err)
	}
}
