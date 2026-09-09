package edgecheck

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

type managedFixtureOptions struct {
	resourceMetadataPath string
	htmlTokenProbe       bool
	mutateDCRCallback    bool
	missingRefreshGrant  bool
	nonHTTPSMetadata     bool
	tools                []string
}

func TestCheckAcceptsCloudflareManagedOAuthContract(t *testing.T) {
	fixture := newManagedFixture(t, managedFixtureOptions{})
	defer fixture.Close()

	result, err := Check(t.Context(), fixture.Client(), Options{
		MCPURL:          fixture.URL + "/mcp",
		ChatGPTRedirect: "https://chatgpt.com/connector_platform_oauth_redirect",
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if result.AuthMode != "cloudflare-managed" {
		t.Fatalf("AuthMode = %q", result.AuthMode)
	}
	if result.AuthorizationHost == "" {
		t.Fatal("AuthorizationHost is empty")
	}
	if result.ToolCount != -1 {
		t.Fatalf("ToolCount = %d, want -1 for unauthenticated qualification", result.ToolCount)
	}
}

func TestCheckRejectsNativeResourceMetadataPath(t *testing.T) {
	fixture := newManagedFixture(t, managedFixtureOptions{resourceMetadataPath: "/.well-known/oauth-protected-resource/mcp"})
	defer fixture.Close()

	_, err := Check(t.Context(), fixture.Client(), Options{MCPURL: fixture.URL + "/mcp", Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "cloudflare-access-protected-resource") {
		t.Fatalf("error = %v, want Cloudflare resource metadata path rejection", err)
	}
}

func TestCheckRejectsHTMLTokenInterstitial(t *testing.T) {
	fixture := newManagedFixture(t, managedFixtureOptions{htmlTokenProbe: true})
	defer fixture.Close()

	_, err := Check(t.Context(), fixture.Client(), Options{MCPURL: fixture.URL + "/mcp", Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "token probe") || !strings.Contains(err.Error(), "html") {
		t.Fatalf("error = %v, want sanitized HTML token-probe rejection", err)
	}
}

func TestCheckRejectsDCRCallbackMutation(t *testing.T) {
	fixture := newManagedFixture(t, managedFixtureOptions{mutateDCRCallback: true})
	defer fixture.Close()

	_, err := Check(t.Context(), fixture.Client(), Options{
		MCPURL:          fixture.URL + "/mcp",
		ChatGPTRedirect: "https://chatgpt.com/connector_platform_oauth_redirect",
		Timeout:         2 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("error = %v, want DCR redirect mutation rejection", err)
	}
}

func TestCheckRejectsMissingRefreshGrant(t *testing.T) {
	fixture := newManagedFixture(t, managedFixtureOptions{missingRefreshGrant: true})
	defer fixture.Close()

	_, err := Check(t.Context(), fixture.Client(), Options{MCPURL: fixture.URL + "/mcp", Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "refresh_token") {
		t.Fatalf("error = %v, want missing refresh grant rejection", err)
	}
}

func TestCheckRejectsNonHTTPSMetadataInProductionMode(t *testing.T) {
	fixture := newManagedFixture(t, managedFixtureOptions{nonHTTPSMetadata: true})
	defer fixture.Close()

	_, err := Check(t.Context(), fixture.Client(), Options{MCPURL: fixture.URL + "/mcp", Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("error = %v, want non-HTTPS metadata rejection", err)
	}
}

func TestCheckAuthenticatedValidatesExactTools(t *testing.T) {
	fixture := newManagedFixture(t, managedFixtureOptions{tools: append([]string(nil), defaultExpectedTools...)})
	defer fixture.Close()

	result, err := Check(t.Context(), fixture.Client(), Options{
		MCPURL:          fixture.URL + "/mcp",
		ChatGPTRedirect: "https://chatgpt.com/connector_platform_oauth_redirect",
		AccessToken:     "edge-test-access-token",
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if result.ToolCount != len(defaultExpectedTools) {
		t.Fatalf("ToolCount = %d, want %d", result.ToolCount, len(defaultExpectedTools))
	}
}

func TestCheckAuthenticatedRejectsExtraTool(t *testing.T) {
	tools := append([]string(nil), defaultExpectedTools...)
	tools = append(tools, "unexpected_tool")
	fixture := newManagedFixture(t, managedFixtureOptions{tools: tools})
	defer fixture.Close()
	const accessToken = "edge-test-access-token"

	_, err := Check(t.Context(), fixture.Client(), Options{
		MCPURL:      fixture.URL + "/mcp",
		AccessToken: accessToken,
		Timeout:     2 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "tool set") {
		t.Fatalf("error = %v, want exact tool-set rejection", err)
	}
	if strings.Contains(err.Error(), accessToken) {
		t.Fatalf("error leaked access token: %v", err)
	}
}

func newManagedFixture(t *testing.T, opts managedFixtureOptions) *httptest.Server {
	t.Helper()
	if opts.resourceMetadataPath == "" {
		opts.resourceMetadataPath = "/.well-known/cloudflare-access-protected-resource/mcp"
	}
	var baseURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			handleFixtureMCP(t, w, r, baseURL, opts)
		case opts.resourceMetadataPath:
			writeFixtureJSON(w, http.StatusOK, map[string]any{
				"resource":              baseURL + "/mcp",
				"authorization_servers": []string{baseURL},
			})
		case "/.well-known/oauth-authorization-server":
			grants := []string{"authorization_code", "refresh_token"}
			if opts.missingRefreshGrant {
				grants = []string{"authorization_code"}
			}
			writeFixtureJSON(w, http.StatusOK, map[string]any{
				"issuer":                                baseURL,
				"authorization_endpoint":                baseURL + "/authorize",
				"token_endpoint":                        baseURL + "/token",
				"registration_endpoint":                 baseURL + "/register",
				"grant_types_supported":                 grants,
				"token_endpoint_auth_methods_supported": []string{"none"},
				"code_challenge_methods_supported":      []string{"S256"},
			})
		case "/token":
			if opts.htmlTokenProbe {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cf-Ray", "fixture-ray")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("<html><body>interstitial</body></html>"))
				return
			}
			if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" {
				writeFixtureJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
				return
			}
			writeFixtureJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		case "/register":
			var registration struct {
				ClientName              string   `json:"client_name"`
				RedirectURIs            []string `json:"redirect_uris"`
				GrantTypes              []string `json:"grant_types"`
				ResponseTypes           []string `json:"response_types"`
				TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
				ApplicationType         string   `json:"application_type"`
			}
			if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
				writeFixtureJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
				return
			}
			if registration.ClientName != "ChatGPT" || len(registration.RedirectURIs) != 1 ||
				!slices.Equal(registration.GrantTypes, []string{"authorization_code", "refresh_token"}) ||
				!slices.Equal(registration.ResponseTypes, []string{"code"}) || registration.TokenEndpointAuthMethod != "none" ||
				registration.ApplicationType != "web" {
				writeFixtureJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
				return
			}
			redirects := registration.RedirectURIs
			if opts.mutateDCRCallback {
				redirects = []string{"https://mutated.example/callback"}
			}
			writeFixtureJSON(w, http.StatusCreated, map[string]any{
				"client_id":        "fixture-client",
				"redirect_uris":    redirects,
				"application_type": "web",
			})
		case "/authorize":
			if r.URL.Query().Get("response_type") != "code" || r.URL.Query().Get("client_id") != "fixture-client" ||
				r.URL.Query().Get("code_challenge_method") != "S256" || r.URL.Query().Get("code_challenge") == "" {
				writeFixtureJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
				return
			}
			http.Redirect(w, r, "https://identity.example/login", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	baseURL = server.URL
	return server
}

func handleFixtureMCP(t *testing.T, w http.ResponseWriter, r *http.Request, baseURL string, opts managedFixtureOptions) {
	t.Helper()
	method := r.Header.Get("Mcp-Method")
	if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
		http.Error(w, "bad protocol version", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Authorization") == "Bearer edge-test-access-token" {
		switch method {
		case "server/discover":
			writeFixtureJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"capabilities": map[string]any{}}})
		case "tools/list":
			tools := opts.tools
			if tools == nil {
				tools = defaultExpectedTools
			}
			entries := make([]map[string]string, 0, len(tools))
			for _, name := range tools {
				entries = append(entries, map[string]string{"name": name})
			}
			writeFixtureJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 2, "result": map[string]any{"tools": entries}})
		default:
			http.Error(w, "unexpected MCP method", http.StatusBadRequest)
		}
		return
	}
	if method != "server/discover" {
		http.Error(w, "expected unauthenticated server/discover", http.StatusBadRequest)
		return
	}
	metadataURL := baseURL + opts.resourceMetadataPath
	if opts.nonHTTPSMetadata {
		metadataURL = "http://" + strings.TrimPrefix(baseURL, "https://") + opts.resourceMetadataPath
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="OAuth", error="invalid_token", resource_metadata=%q`, metadataURL))
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
}

func writeFixtureJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
