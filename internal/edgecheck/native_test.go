package edgecheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckNativeQualifiesAWSParityContract(t *testing.T) {
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": server.URL + "/mcp", "authorization_servers": []string{server.URL}, "bearer_methods_supported": []string{"header"}, "scopes_supported": []string{"mcp"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                         server.URL,
			"authorization_endpoint":                         server.URL + "/oauth/authorize",
			"token_endpoint":                                 server.URL + "/oauth/token",
			"registration_endpoint":                          server.URL + "/oauth/register",
			"revocation_endpoint":                            server.URL + "/oauth/revoke",
			"response_types_supported":                       []string{"code"},
			"response_modes_supported":                       []string{"query"},
			"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
			"token_endpoint_auth_methods_supported":          []string{"none"},
			"code_challenge_methods_supported":               []string{"S256"},
			"client_id_metadata_document_supported":          true,
			"authorization_response_iss_parameter_supported": true,
			"protected_resources":                            []string{server.URL + "/mcp"},
		})
	})
	mux.HandleFunc("/oauth/register", func(w http.ResponseWriter, r *http.Request) {
		var input map[string]any
		_ = json.NewDecoder(r.Body).Decode(&input)
		redirects, _ := input["redirect_uris"].([]any)
		redirect := ""
		if len(redirects) == 1 {
			redirect, _ = redirects[0].(string)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "urn:test:client", "redirect_uris": []string{redirect}, "application_type": "web"})
	})
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", server.URL+"/oauth/login?ticket=signed-test-ticket")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"invalid refresh token"}`))
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	server = httptest.NewTLSServer(mux)
	defer server.Close()

	result, err := CheckNative(t.Context(), server.Client(), NativeOptions{Origin: server.URL, Resource: server.URL + "/mcp", ChatGPTRedirect: "https://chatgpt.com/connector_platform_oauth_redirect"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Issuer != server.URL || result.DCRApplicationType != "web" || !result.RevocationAdvertised || !result.CIMDSupported {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestCheckNativeRejectsMissingQueryResponseMode(t *testing.T) {
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": server.URL + "/mcp", "authorization_servers": []string{server.URL}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "authorization_endpoint": server.URL + "/oauth/authorize", "token_endpoint": server.URL + "/oauth/token", "registration_endpoint": server.URL + "/oauth/register", "revocation_endpoint": server.URL + "/oauth/revoke", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"none"}, "code_challenge_methods_supported": []string{"S256"}, "client_id_metadata_document_supported": true, "protected_resources": []string{server.URL + "/mcp"}})
	})
	server = httptest.NewTLSServer(mux)
	defer server.Close()
	_, err := CheckNative(t.Context(), server.Client(), NativeOptions{Origin: server.URL, Resource: server.URL + "/mcp"})
	if err == nil || !strings.Contains(err.Error(), "AWS-parity capabilities") {
		t.Fatalf("err=%v", err)
	}
}
