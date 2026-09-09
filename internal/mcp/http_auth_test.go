package mcpx

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/heidi-dang/superfast-mcp/internal/access"
	oauthserver "github.com/heidi-dang/superfast-mcp/internal/oauth"
)

type fakeAccessVerifier struct {
	identity      access.Identity
	err           error
	lastAssertion string
}

func (f *fakeAccessVerifier) Verify(_ context.Context, assertion string) (access.Identity, error) {
	f.lastAssertion = assertion
	return f.identity, f.err
}

func authSuccessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestMCPAuthAcceptsCloudflareAccessAssertion(t *testing.T) {
	verifier := &fakeAccessVerifier{identity: access.Identity{Subject: "owner", Email: "owner@example.com", Scope: "mcp"}}
	handler := authenticateMCP(mcpAuthOptions{Access: verifier}, authSuccessHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", "valid-access-assertion")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if verifier.lastAssertion != "valid-access-assertion" {
		t.Fatalf("verified assertion = %q", verifier.lastAssertion)
	}
}

func TestMCPAuthRejectsInvalidCloudflareAssertion(t *testing.T) {
	verifier := &fakeAccessVerifier{err: errors.New("invalid assertion")}
	handler := authenticateMCP(mcpAuthOptions{Access: verifier}, authSuccessHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", "invalid-access-assertion")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMCPAuthFallsBackToStaticBearer(t *testing.T) {
	verifier := &fakeAccessVerifier{err: errors.New("invalid assertion")}
	handler := authenticateMCP(mcpAuthOptions{StaticToken: "break-glass-token", Access: verifier}, authSuccessHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", "invalid-access-assertion")
	req.Header.Set("Authorization", "Bearer break-glass-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestMCPAuthFallsBackToNativeOAuth(t *testing.T) {
	oauthServer, accessToken := nativeOAuthServerAndAccessToken(t)
	verifier := &fakeAccessVerifier{err: errors.New("invalid assertion")}
	handler := authenticateMCP(mcpAuthOptions{StaticToken: "different-static-token", Access: verifier, NativeOAuth: oauthServer}, authSuccessHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", "invalid-access-assertion")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestMCPAuthRejectsMissingCredentials(t *testing.T) {
	oauthServer, _ := nativeOAuthServerAndAccessToken(t)
	handler := authenticateMCP(mcpAuthOptions{StaticToken: "break-glass-token", NativeOAuth: oauthServer}, authSuccessHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, oauthServer.ResourceMetadataURL()) {
		t.Fatalf("challenge = %q, want native OAuth resource metadata URL", challenge)
	}
}

func TestMCPAuthDoesNotTrustCfAssertionWithoutVerifier(t *testing.T) {
	handler := authenticateMCP(mcpAuthOptions{StaticToken: "break-glass-token"}, authSuccessHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", "unverified-header-value")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func nativeOAuthServerAndAccessToken(t *testing.T) (*oauthserver.Server, string) {
	t.Helper()
	const (
		issuer      = "https://native.example"
		resource    = issuer + "/mcp"
		masterToken = "native-oauth-master-token"
		redirectURI = "https://chatgpt.example/callback"
	)

	server, err := oauthserver.New(issuer, resource, masterToken, "")
	if err != nil {
		t.Fatalf("create native OAuth server: %v", err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	registration := `{"redirect_uris":["https://chatgpt.example/callback"],"client_name":"auth-test","grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"web"}`
	registerReq := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(registration))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRec := httptest.NewRecorder()
	mux.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body=%s", registerRec.Code, registerRec.Body.String())
	}
	var registrationResult struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(registerRec.Body.Bytes(), &registrationResult); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}

	codeVerifier := strings.Repeat("v", 64)
	challengeBytes := sha256.Sum256([]byte(codeVerifier))
	authorizeQuery := url.Values{
		"response_type":         {"code"},
		"client_id":             {registrationResult.ClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challengeBytes[:])},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
		"scope":                 {"mcp"},
	}
	authorizeReq := httptest.NewRequest(http.MethodPost, "/authorize?"+authorizeQuery.Encode(), strings.NewReader(url.Values{
		"owner_password": {oauthserver.OwnerPasswordFromToken(masterToken)},
	}.Encode()))
	authorizeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authorizeRec := httptest.NewRecorder()
	mux.ServeHTTP(authorizeRec, authorizeReq)
	if authorizeRec.Code != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, body=%s", authorizeRec.Code, authorizeRec.Body.String())
	}
	redirect, err := url.Parse(authorizeRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorization redirect: %v", err)
	}
	authorizationCode := redirect.Query().Get("code")
	if authorizationCode == "" {
		t.Fatal("authorization redirect missing code")
	}

	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {registrationResult.ClientID},
		"redirect_uri":  {redirectURI},
		"code":          {authorizationCode},
		"code_verifier": {codeVerifier},
		"resource":      {resource},
	}.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	mux.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status = %d, body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokenResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokenResult); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResult.AccessToken == "" {
		t.Fatal("token response missing access_token")
	}
	return server, tokenResult.AccessToken
}
