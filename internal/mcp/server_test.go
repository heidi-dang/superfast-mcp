package mcpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestHTTPHandlerPublishesOAuthDiscovery(t *testing.T) {
	cfg := testConfig(t)
	cfg.PublicURL = "https://superfast.example.com"
	handler, err := NewHTTPHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

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
		`"authorization_endpoint":"https://superfast.example.com/authorize"`,
		`"token_endpoint":"https://superfast.example.com/token"`,
		`"registration_endpoint":"https://superfast.example.com/register"`,
		`"S256"`,
	} {
		if !strings.Contains(authMetadataBody, want) {
			t.Fatalf("authorization metadata missing %s: %s", want, authMetadataBody)
		}
	}

	mcpReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	mcpRec := httptest.NewRecorder()
	handler.ServeHTTP(mcpRec, mcpReq)
	if mcpRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated MCP status = %d, want 401", mcpRec.Code)
	}
	challenge := mcpRec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="https://superfast.example.com/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("OAuth challenge missing resource metadata URL: %q", challenge)
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
