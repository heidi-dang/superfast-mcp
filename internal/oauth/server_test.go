package oauth

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testNativeIssuer = "https://superfast.example.com"
const testNativeResource = testNativeIssuer + "/mcp"
const testChatGPTRedirect = "https://chatgpt.com/connector_platform_oauth_redirect"

func newTestNativeServer(t *testing.T) *Server {
	t.Helper()
	server, err := New(ServerConfig{
		Issuer:   testNativeIssuer,
		Resource: testNativeResource,
		Scopes:   []string{"mcp"},
		Secret:   strings.Repeat("s", 48),
		StateDB:  filepath.Join(t.TempDir(), "oauth.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func registerTestClient(t *testing.T, server *Server, redirectURI, applicationType string) string {
	t.Helper()
	mux := http.NewServeMux()
	server.RegisterProtocolRoutes(mux)
	body := `{"client_name":"ChatGPT","redirect_uris":["` + redirectURI + `"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"` + applicationType + `"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		ClientID        string   `json:"client_id"`
		RedirectURIs    []string `json:"redirect_uris"`
		ApplicationType string   `json:"application_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ClientID == "" || response.ApplicationType != applicationType || len(response.RedirectURIs) != 1 || response.RedirectURIs[0] != redirectURI {
		t.Fatalf("registration=%+v", response)
	}
	return response.ClientID
}

func authorizationTicket(t *testing.T, server *Server, clientID, redirectURI, state string) string {
	t.Helper()
	mux := http.NewServeMux()
	server.RegisterProtocolRoutes(mux)
	verifier := strings.Repeat("v", 64)
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"resource":              {testNativeResource},
		"scope":                 {"mcp"},
		"code_challenge":        {PKCES256(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Scheme+"://"+location.Host+location.Path != testNativeIssuer+"/oauth/login" {
		t.Fatalf("login redirect=%q", location.String())
	}
	ticket := location.Query().Get("ticket")
	if ticket == "" {
		t.Fatal("authorization redirect missing ticket")
	}
	return ticket
}

func approveTicket(t *testing.T, server *Server, ticket string) *url.URL {
	t.Helper()
	form := url.Values{"ticket": {ticket}, "decision": {"approve"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	server.HandleLogin(rec, req, Identity{Subject: "owner-subject", Email: "owner@example.com"})
	if rec.Code != http.StatusFound {
		t.Fatalf("login approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	callback, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return callback
}

func TestNativeOAuthMetadataMatchesAWSParity(t *testing.T) {
	server := newTestNativeServer(t)
	mux := http.NewServeMux()
	server.RegisterProtocolRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status=%d body=%s", rec.Code, rec.Body.String())
	}
	var metadata map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"issuer":                 testNativeIssuer,
		"authorization_endpoint": testNativeIssuer + "/oauth/authorize",
		"token_endpoint":         testNativeIssuer + "/oauth/token",
		"registration_endpoint":  testNativeIssuer + "/oauth/register",
		"revocation_endpoint":    testNativeIssuer + "/oauth/revoke",
	} {
		if metadata[key] != want {
			t.Fatalf("metadata[%s]=%v want %q", key, metadata[key], want)
		}
	}
	if metadata["client_id_metadata_document_supported"] != true {
		t.Fatalf("CIMD support=%v", metadata["client_id_metadata_document_supported"])
	}
	if metadata["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("RFC 9207 iss support=%v", metadata["authorization_response_iss_parameter_supported"])
	}
	for _, key := range []string{"response_modes_supported", "grant_types_supported", "token_endpoint_auth_methods_supported", "code_challenge_methods_supported", "protected_resources", "scopes_supported"} {
		if _, ok := metadata[key]; !ok {
			t.Fatalf("metadata missing %s: %v", key, metadata)
		}
	}

	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"authorization_servers":["https://superfast.example.com"]`) || !strings.Contains(rec.Body.String(), `"resource":"https://superfast.example.com/mcp"`) {
			t.Fatalf("protected metadata path=%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestNativeOAuthDCRPreservesChatGPTApplicationType(t *testing.T) {
	server := newTestNativeServer(t)
	clientID := registerTestClient(t, server, testChatGPTRedirect, "web")
	if !strings.HasPrefix(clientID, dynamicClientPrefix) {
		t.Fatalf("clientID=%q", clientID)
	}
}

func TestAuthorizeRedirectsToSignedLoginTicketAndRejectsInvalidRequests(t *testing.T) {
	server := newTestNativeServer(t)
	clientID := registerTestClient(t, server, testChatGPTRedirect, "web")
	_ = authorizationTicket(t, server, clientID, testChatGPTRedirect, "state-1")

	mux := http.NewServeMux()
	server.RegisterProtocolRoutes(mux)
	base := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testChatGPTRedirect},
		"resource": {testNativeResource}, "scope": {"mcp"}, "code_challenge": {PKCES256(strings.Repeat("v", 64))}, "code_challenge_method": {"S256"},
	}
	cases := []url.Values{cloneValues(base), cloneValues(base), cloneValues(base), cloneValues(base), cloneValues(base)}
	cases[0].Set("resource", "https://wrong.example.com/mcp")
	cases[1].Set("redirect_uri", "https://wrong.example.com/callback")
	cases[2].Del("code_challenge")
	cases[3].Set("scope", "admin")
	cases[4].Set("response_type", "token")
	for i, query := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("case %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestLoginConsentApproveDenyAndRFC9207Issuer(t *testing.T) {
	server := newTestNativeServer(t)
	clientID := registerTestClient(t, server, testChatGPTRedirect, "web")
	ticket := authorizationTicket(t, server, clientID, testChatGPTRedirect, "state-2026")

	getReq := httptest.NewRequest(http.MethodGet, "/oauth/login?ticket="+url.QueryEscape(ticket), nil)
	getRec := httptest.NewRecorder()
	server.HandleLogin(getRec, getReq, Identity{Subject: "owner-subject", Email: "owner@example.com"})
	if getRec.Code != http.StatusOK {
		t.Fatalf("login GET status=%d body=%s", getRec.Code, getRec.Body.String())
	}
	body := getRec.Body.String()
	for _, want := range []string{"ChatGPT", testNativeResource, "mcp"} {
		if !strings.Contains(body, want) {
			t.Fatalf("consent missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "owner_password") {
		t.Fatal("consent page still contains owner password")
	}

	callback := approveTicket(t, server, ticket)
	if callback.Query().Get("code") == "" || callback.Query().Get("state") != "state-2026" || callback.Query().Get("iss") != testNativeIssuer {
		t.Fatalf("approve callback=%s", callback.String())
	}

	denyTicket := authorizationTicket(t, server, clientID, testChatGPTRedirect, "deny-state")
	form := url.Values{"ticket": {denyTicket}, "decision": {"deny"}}
	denyReq := httptest.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader(form.Encode()))
	denyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	denyRec := httptest.NewRecorder()
	server.HandleLogin(denyRec, denyReq, Identity{Subject: "owner-subject", Email: "owner@example.com"})
	if denyRec.Code != http.StatusFound {
		t.Fatalf("deny status=%d body=%s", denyRec.Code, denyRec.Body.String())
	}
	denied, _ := url.Parse(denyRec.Header().Get("Location"))
	if denied.Query().Get("error") != "access_denied" || denied.Query().Get("state") != "deny-state" || denied.Query().Get("iss") != testNativeIssuer {
		t.Fatalf("deny callback=%s", denied.String())
	}
}

func TestAuthorizationCodeRefreshRotationReuseAndRevoke(t *testing.T) {
	server := newTestNativeServer(t)
	clientID := registerTestClient(t, server, testChatGPTRedirect, "web")
	verifier := strings.Repeat("v", 64)
	ticket := authorizationTicket(t, server, clientID, testChatGPTRedirect, "token-state")
	callback := approveTicket(t, server, ticket)
	code := callback.Query().Get("code")

	mux := http.NewServeMux()
	server.RegisterProtocolRoutes(mux)
	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {testChatGPTRedirect},
		"code": {code}, "code_verifier": {verifier}, "resource": {testNativeResource},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	mux.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokenBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokenBody); err != nil {
		t.Fatal(err)
	}
	if tokenBody.AccessToken == "" || tokenBody.RefreshToken == "" || tokenBody.TokenType != "Bearer" || tokenBody.ExpiresIn != 900 || tokenBody.Scope != "mcp" {
		t.Fatalf("token response=%+v", tokenBody)
	}
	if !server.VerifyAccessToken(tokenBody.AccessToken) {
		t.Fatal("issued access token did not verify")
	}

	refresh := func(refreshToken string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refreshToken}, "resource": {testNativeResource}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	refreshed := refresh(tokenBody.RefreshToken)
	if refreshed.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refreshed.Code, refreshed.Body.String())
	}
	var refreshedBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(refreshed.Body.Bytes(), &refreshedBody); err != nil {
		t.Fatal(err)
	}
	if refreshedBody.RefreshToken == "" || refreshedBody.RefreshToken == tokenBody.RefreshToken {
		t.Fatalf("refresh did not rotate: %+v", refreshedBody)
	}
	if rec := refresh(tokenBody.RefreshToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("refresh reuse status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := refresh(refreshedBody.RefreshToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("family after reuse status=%d body=%s", rec.Code, rec.Body.String())
	}

	secondCodeTicket := authorizationTicket(t, server, clientID, testChatGPTRedirect, "revoke-state")
	secondCallback := approveTicket(t, server, secondCodeTicket)
	secondForm := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {testChatGPTRedirect},
		"code": {secondCallback.Query().Get("code")}, "code_verifier": {verifier}, "resource": {testNativeResource},
	}
	secondReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(secondForm.Encode()))
	secondReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	secondRec := httptest.NewRecorder()
	mux.ServeHTTP(secondRec, secondReq)
	var secondTokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(secondRec.Body.Bytes(), &secondTokens); err != nil {
		t.Fatal(err)
	}
	revokeForm := url.Values{"token": {secondTokens.RefreshToken}}
	revokeReq := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(revokeForm.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRec := httptest.NewRecorder()
	mux.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK || strings.TrimSpace(revokeRec.Body.String()) != "{}" {
		t.Fatalf("revoke status=%d body=%s", revokeRec.Code, revokeRec.Body.String())
	}
	if rec := refresh(secondTokens.RefreshToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("revoked refresh status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOAuthTokenHandlingDoesNotLogGrantMaterial(t *testing.T) {
	server := newTestNativeServer(t)
	mux := http.NewServeMux()
	server.RegisterProtocolRoutes(mux)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	form := url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"invalid-client"},
		"refresh_token": {"refresh-secret-must-not-be-logged"}, "resource": {testNativeResource},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer must-not-be-logged")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), "refresh-secret-must-not-be-logged") || strings.Contains(logs.String(), "must-not-be-logged") {
		t.Fatalf("credential leaked to log: %s", logs.String())
	}
}

func cloneValues(input url.Values) url.Values {
	out := make(url.Values, len(input))
	for key, values := range input {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func TestNativeOAuthDefaultsMatchAWSLifetimes(t *testing.T) {
	server := newTestNativeServer(t)
	if server.accessTokenTTL != 15*time.Minute || server.grantTTL != 14*24*time.Hour || server.authorizationCodeTTL != 5*time.Minute {
		t.Fatalf("ttl access=%s grant=%s code=%s", server.accessTokenTTL, server.grantTTL, server.authorizationCodeTTL)
	}
}
