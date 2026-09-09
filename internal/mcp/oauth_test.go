package mcpx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPHandlerOAuthAuthorizationCodeFlow(t *testing.T) {
	cfg := testConfig(t)
	cfg.PublicURL = "https://superfast.example.com"
	handler, err := NewHTTPHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	registration := `{"redirect_uris":["https://chatgpt.example/callback"],"client_name":"ChatGPT","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"web"}`
	registerReq := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(registration))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body=%s", registerRec.Code, registerRec.Body.String())
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(registerRec.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	if registered.ClientID == "" {
		t.Fatal("registration returned empty client_id")
	}

	verifier := strings.Repeat("v", 64)
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	ownerMAC := hmac.New(sha256.New, []byte(cfg.AuthToken))
	_, _ = ownerMAC.Write([]byte("superfast-mcp/oauth-owner/v1"))
	ownerPassword := hex.EncodeToString(ownerMAC.Sum(nil))
	authorizeQuery := url.Values{
		"response_type":         {"code"},
		"client_id":             {registered.ClientID},
		"redirect_uri":          {"https://chatgpt.example/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"state-123"},
		"resource":              {"https://superfast.example.com/mcp"},
		"scope":                 {"mcp offline_access"},
	}
	authorizePath := "/authorize?" + authorizeQuery.Encode()
	authorizePageReq := httptest.NewRequest(http.MethodGet, authorizePath, nil)
	authorizePageRec := httptest.NewRecorder()
	handler.ServeHTTP(authorizePageRec, authorizePageReq)
	if authorizePageRec.Code != http.StatusOK || !strings.Contains(authorizePageRec.Body.String(), "Owner authorization password") {
		t.Fatalf("authorization page failed: status=%d body=%s", authorizePageRec.Code, authorizePageRec.Body.String())
	}
	authorizeReq := httptest.NewRequest(http.MethodPost, authorizePath, strings.NewReader(url.Values{"owner_password": {ownerPassword}}.Encode()))
	authorizeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authorizeRec := httptest.NewRecorder()
	handler.ServeHTTP(authorizeRec, authorizeReq)
	if authorizeRec.Code != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, want 303; body=%s", authorizeRec.Code, authorizeRec.Body.String())
	}
	redirect, err := url.Parse(authorizeRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Scheme != "https" || redirect.Host != "chatgpt.example" || redirect.Path != "/callback" {
		t.Fatalf("unexpected authorization redirect: %s", redirect)
	}
	if redirect.Query().Get("state") != "state-123" || redirect.Query().Get("iss") != "https://superfast.example.com" {
		t.Fatalf("authorization redirect missing state/iss: %s", redirect)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatal("authorization redirect missing code")
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {registered.ClientID},
		"redirect_uri":  {"https://chatgpt.example/callback"},
		"code":          {code},
		"code_verifier": {verifier},
		"resource":      {"https://superfast.example.com/mcp"},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	handler.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status = %d, want 200; body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("missing OAuth tokens: %s", tokenRec.Body.String())
	}

	mcpBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"oauth-test","version":"1"}}}}`
	mcpReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpBody))
	mcpReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("Accept", "application/json, text/event-stream")
	mcpReq.Header.Set("MCP-Protocol-Version", "2026-07-28")
	mcpReq.Header.Set("Mcp-Method", "tools/list")
	mcpRec := httptest.NewRecorder()
	handler.ServeHTTP(mcpRec, mcpReq)
	if mcpRec.Code != http.StatusOK {
		t.Fatalf("OAuth-authenticated MCP status = %d, want 200; body=%s", mcpRec.Code, mcpRec.Body.String())
	}

	replayReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRec := httptest.NewRecorder()
	handler.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusBadRequest || !strings.Contains(replayRec.Body.String(), `"error":"invalid_grant"`) {
		t.Fatalf("authorization code replay was not rejected: status=%d body=%s", replayRec.Code, replayRec.Body.String())
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {registered.ClientID},
		"refresh_token": {tokens.RefreshToken},
		"resource":      {"https://superfast.example.com/mcp"},
	}
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	handler.ServeHTTP(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK || !strings.Contains(refreshRec.Body.String(), `"access_token"`) {
		t.Fatalf("refresh token exchange failed: status=%d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
}
