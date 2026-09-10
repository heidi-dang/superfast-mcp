package mcpx

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heidi-dang/superfast-mcp/internal/access"
	"github.com/heidi-dang/superfast-mcp/internal/config"
)

func nativeHTTPTestConfig(t *testing.T) *config.Config {
	t.Helper()
	issuer := "https://superfast.example.com"
	return &config.Config{
		Roots: []string{t.TempDir()}, Version: "test", AuthToken: "break-glass", PublicURL: issuer,
		CloudflareAccess: &config.CloudflareAccessConfig{Issuer: "https://team.cloudflareaccess.com", Audience: "app-aud", AllowedEmail: "owner@example.com", JWKSURL: "https://team.cloudflareaccess.com/cdn-cgi/access/certs", Resource: issuer + "/mcp"},
		NativeOAuth:      &config.NativeOAuthConfig{Issuer: issuer, Resource: issuer + "/mcp", Scopes: []string{"mcp"}, Secret: strings.Repeat("n", 48), StateDB: filepath.Join(t.TempDir(), "oauth.db")},
	}
}

func registerAndAuthorize(t *testing.T, handler http.Handler, assertion string) (clientID, verifier, code string) {
	t.Helper()
	registration := `{"redirect_uris":["https://chatgpt.example/callback"],"client_name":"ChatGPT","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"web"}`
	registerReq := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(registration))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", registerRec.Code, registerRec.Body.String())
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(registerRec.Body.Bytes(), &registered); err != nil || registered.ClientID == "" {
		t.Fatalf("decode registration: id=%q err=%v", registered.ClientID, err)
	}

	verifier = strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {registered.ClientID}, "redirect_uri": {"https://chatgpt.example/callback"}, "resource": {"https://superfast.example.com/mcp"}, "scope": {"mcp"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "state": {"state-123"}}
	authorizeReq := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	authorizeRec := httptest.NewRecorder()
	handler.ServeHTTP(authorizeRec, authorizeReq)
	if authorizeRec.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", authorizeRec.Code, authorizeRec.Body.String())
	}
	loginURL, err := url.Parse(authorizeRec.Header().Get("Location"))
	if err != nil || loginURL.Path != "/oauth/login" || loginURL.Query().Get("ticket") == "" {
		t.Fatalf("bad login redirect=%q err=%v", authorizeRec.Header().Get("Location"), err)
	}
	ticket := loginURL.Query().Get("ticket")

	missingReq := httptest.NewRequest(http.MethodGet, "/oauth/login?ticket="+url.QueryEscape(ticket), nil)
	missingRec := httptest.NewRecorder()
	handler.ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusUnauthorized {
		t.Fatalf("login without Access status=%d, want 401", missingRec.Code)
	}

	consentReq := httptest.NewRequest(http.MethodGet, "/oauth/login?ticket="+url.QueryEscape(ticket), nil)
	consentReq.Header.Set("Cf-Access-Jwt-Assertion", assertion)
	consentRec := httptest.NewRecorder()
	handler.ServeHTTP(consentRec, consentReq)
	if consentRec.Code != http.StatusOK || !strings.Contains(consentRec.Body.String(), "Approve") || strings.Contains(strings.ToLower(consentRec.Body.String()), "owner password") {
		t.Fatalf("consent status=%d body=%s", consentRec.Code, consentRec.Body.String())
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader(url.Values{"ticket": {ticket}, "decision": {"approve"}}.Encode()))
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveReq.Header.Set("Cf-Access-Jwt-Assertion", assertion)
	approveRec := httptest.NewRecorder()
	handler.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusFound {
		t.Fatalf("approve status=%d body=%s", approveRec.Code, approveRec.Body.String())
	}
	callback, err := url.Parse(approveRec.Header().Get("Location"))
	if err != nil || callback.Query().Get("state") != "state-123" || callback.Query().Get("iss") != "https://superfast.example.com" {
		t.Fatalf("bad callback=%q err=%v", approveRec.Header().Get("Location"), err)
	}
	code = callback.Query().Get("code")
	if code == "" {
		t.Fatal("authorization callback missing code")
	}
	return registered.ClientID, verifier, code
}

func exchangeCode(t *testing.T, handler http.Handler, clientID, verifier, code string) (accessToken, refreshToken string) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {"https://chatgpt.example/callback"}, "code": {code}, "code_verifier": {verifier}, "resource": {"https://superfast.example.com/mcp"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatalf("bad token response err=%v body=%s", err, rec.Body.String())
	}
	return result.AccessToken, result.RefreshToken
}

func TestNativeOAuthLoginFailsClosedWithoutCloudflareAssertion(t *testing.T) {
	cfg := nativeHTTPTestConfig(t)
	verifier := &fakeAccessVerifier{identity: access.Identity{Subject: "owner-sub", Email: "owner@example.com"}}
	handler, err := newHTTPHandler(cfg, verifier)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	registerAndAuthorize(t, handler, "valid-access")
}

func TestNativeOAuthEndToEndAuthenticatesEightMCPTools(t *testing.T) {
	cfg := nativeHTTPTestConfig(t)
	verifier := &fakeAccessVerifier{identity: access.Identity{Subject: "owner-sub", Email: "owner@example.com"}}
	handler, err := newHTTPHandler(cfg, verifier)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })

	clientID, pkceVerifier, code := registerAndAuthorize(t, handler, "valid-access")
	accessToken, refreshToken := exchangeCode(t, handler, clientID, pkceVerifier, code)
	mcpReq := newToolsListRequest("/mcp")
	mcpReq.Header.Set("Authorization", "Bearer "+accessToken)
	mcpRec := httptest.NewRecorder()
	handler.ServeHTTP(mcpRec, mcpReq)
	if mcpRec.Code != http.StatusOK {
		t.Fatalf("tools/list status=%d body=%s", mcpRec.Code, mcpRec.Body.String())
	}
	var mcpBody struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	payload := mcpRec.Body.Bytes()
	if strings.HasPrefix(strings.TrimSpace(string(payload)), "event:") {
		for _, line := range strings.Split(string(payload), "\n") {
			if strings.HasPrefix(line, "data: ") {
				payload = []byte(strings.TrimPrefix(line, "data: "))
				break
			}
		}
	}
	if err := json.Unmarshal(payload, &mcpBody); err != nil {
		t.Fatalf("decode tools/list: %v body=%q content-type=%q", err, mcpRec.Body.String(), mcpRec.Header().Get("Content-Type"))
	}
	var names []string
	for _, tool := range mcpBody.Result.Tools {
		names = append(names, tool.Name)
	}
	want := []string{"git_diff", "git_log", "git_status", "list_dir", "ping", "read_file", "run_command", "write_file"}
	slices.Sort(names)
	if !slices.Equal(names, want) {
		t.Fatalf("tools=%v want=%v", names, want)
	}

	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refreshToken}, "resource": {cfg.NativeOAuth.Resource}}
	refreshReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	handler.ServeHTTP(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshed struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(refreshRec.Body.Bytes(), &refreshed); err != nil || refreshed.RefreshToken == "" || refreshed.RefreshToken == refreshToken {
		t.Fatalf("refresh did not rotate: err=%v body=%s", err, refreshRec.Body.String())
	}

	reuseReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	reuseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuseRec := httptest.NewRecorder()
	handler.ServeHTTP(reuseRec, reuseReq)
	if reuseRec.Code != http.StatusBadRequest {
		t.Fatalf("reused refresh status=%d", reuseRec.Code)
	}
	familyReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refreshed.RefreshToken}, "resource": {cfg.NativeOAuth.Resource}}.Encode()))
	familyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	familyRec := httptest.NewRecorder()
	handler.ServeHTTP(familyRec, familyReq)
	if familyRec.Code != http.StatusBadRequest {
		t.Fatalf("revoked refresh family status=%d", familyRec.Code)
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(url.Values{"token": {"unknown-refresh-token"}}.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d", revokeRec.Code)
	}
}
