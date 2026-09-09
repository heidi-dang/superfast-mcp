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
