package oauth

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func testClientResolver() *ClientResolver {
	return NewClientResolver("https://superfast.example.com", []byte(strings.Repeat("s", 48)))
}

func TestIssueDynamicClientPreservesWebApplicationType(t *testing.T) {
	resolver := testClientResolver()
	clientID, metadata, issuedAt, err := resolver.IssueDynamicClient(ClientRegistrationInput{
		ClientName:              "ChatGPT",
		RedirectURIs:            []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		ApplicationType:         "web",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(clientID, "urn:superfast:oauth-client:") {
		t.Fatalf("clientID=%q", clientID)
	}
	if metadata.ApplicationType != "web" || metadata.TokenEndpointAuthMethod != "none" {
		t.Fatalf("metadata=%+v", metadata)
	}
	if issuedAt <= 0 {
		t.Fatalf("issuedAt=%d", issuedAt)
	}
	resolved, err := resolver.Resolve(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ClientName != "ChatGPT" || resolved.RedirectURIs[0] != "https://chatgpt.com/connector_platform_oauth_redirect" {
		t.Fatalf("resolved=%+v", resolved)
	}
}

func TestIssueDynamicClientPreservesNativeLoopbackApplicationType(t *testing.T) {
	resolver := testClientResolver()
	_, metadata, _, err := resolver.IssueDynamicClient(ClientRegistrationInput{
		ClientName:              "Native MCP Client",
		RedirectURIs:            []string{"http://127.0.0.1:43123/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		ApplicationType:         "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ApplicationType != "native" {
		t.Fatalf("application_type=%q", metadata.ApplicationType)
	}
}

func TestIssueDynamicClientAcceptsClaudeGeminiAndGrokRedirectShapes(t *testing.T) {
	resolver := testClientResolver()
	clients := []ClientRegistrationInput{
		{
			ClientName: "Claude",
			RedirectURIs: []string{
				"https://claude.ai/api/mcp/auth_callback",
				"https://claude.com/api/mcp/auth_callback",
			},
			GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none", ApplicationType: "web",
		},
		{
			ClientName: "Gemini CLI", RedirectURIs: []string{"http://localhost:43123/oauth/callback"},
			GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none", ApplicationType: "native",
		},
		{
			ClientName: "Grok hosted MCP connector", RedirectURIs: []string{
				"https://grok.com/connectors-oauth-exchange-code/",
				"https://grok.com/connectors-oauth-exchange-code",
			},
			GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none", ApplicationType: "web",
		},
	}
	for _, input := range clients {
		t.Run(input.ClientName, func(t *testing.T) {
			clientID, metadata, _, err := resolver.IssueDynamicClient(input)
			if err != nil {
				t.Fatal(err)
			}
			if clientID == "" || len(metadata.RedirectURIs) != len(input.RedirectURIs) || metadata.ApplicationType != input.ApplicationType {
				t.Fatalf("metadata=%+v clientID=%q", metadata, clientID)
			}
		})
	}
}

func TestIssueDynamicClientRejectsPrivateAuthMethodOrMissingAuthorizationCode(t *testing.T) {
	resolver := testClientResolver()
	base := ClientRegistrationInput{
		ClientName: "Bad Client", RedirectURIs: []string{"https://client.example/callback"},
		GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none", ApplicationType: "web",
	}
	cases := []ClientRegistrationInput{base, base, base, base}
	cases[0].TokenEndpointAuthMethod = "client_secret_basic"
	cases[1].GrantTypes = []string{"refresh_token"}
	cases[2].GrantTypes = []string{"authorization_code", "client_credentials"}
	cases[3].ResponseTypes = []string{"token"}
	for i, input := range cases {
		if _, _, _, err := resolver.IssueDynamicClient(input); err == nil {
			t.Fatalf("case %d: expected rejection", i)
		}
	}
}

func TestValidateRedirectURIRejectsFragmentsCredentialsAndNonLoopbackHTTP(t *testing.T) {
	bad := []string{
		"https://client.example/callback#fragment",
		"https://user:pass@client.example/callback",
		"http://client.example/callback",
		"ftp://client.example/callback",
		"/relative/callback",
	}
	for _, raw := range bad {
		if _, err := validateClientRedirectURI(raw); err == nil {
			t.Fatalf("redirect %q should be rejected", raw)
		}
	}
	for _, raw := range []string{"https://client.example/callback", "http://localhost:1234/callback", "http://127.0.0.1:1234/callback", "http://[::1]:1234/callback"} {
		if _, err := validateClientRedirectURI(raw); err != nil {
			t.Fatalf("redirect %q rejected: %v", raw, err)
		}
	}
}

func TestDynamicClientIDRejectsTampering(t *testing.T) {
	resolver := testClientResolver()
	clientID, _, _, err := resolver.IssueDynamicClient(ClientRegistrationInput{
		ClientName: "ChatGPT", RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none", ApplicationType: "web",
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := clientID[:len(clientID)-1] + "x"
	if _, err := resolver.Resolve(context.Background(), tampered); err == nil {
		t.Fatal("tampered dynamic client id was accepted")
	}
}

func TestCIMDRejectsNonHTTPSDefaultPortMissingPathCredentialsAndFragment(t *testing.T) {
	resolver := testClientResolver()
	bad := []string{
		"http://client.example/meta",
		"https://client.example:8443/meta",
		"https://client.example/",
		"https://user:pass@client.example/meta",
		"https://client.example/meta#fragment",
		"https://localhost/meta",
		"https://service.local/meta",
	}
	for _, clientID := range bad {
		if _, err := resolver.Resolve(context.Background(), clientID); err == nil {
			t.Fatalf("CIMD %q should be rejected", clientID)
		}
	}
}

func TestCIMDRejectsLocalAndPrivateResolvedAddresses(t *testing.T) {
	private := []string{
		"0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
		"::", "::1", "fc00::1", "fe80::1", "2001:db8::1", "ff00::1",
	}
	for _, address := range private {
		t.Run(address, func(t *testing.T) {
			resolver := testClientResolver()
			resolver.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
			}
			if _, err := resolver.Resolve(context.Background(), "https://client.example/meta"); err == nil {
				t.Fatalf("private address %s was accepted", address)
			}
		})
	}
}

func TestCIMDRequiresExactClientIDAndJSONBody(t *testing.T) {
	resolver := testClientResolver()
	resolver.lookupIP = publicLookup
	resolver.fetchDocument = func(context.Context, string, net.IPAddr) (cimdFetchResult, error) {
		body, _ := json.Marshal(map[string]any{
			"client_id": "https://wrong.example/meta", "client_name": "Wrong",
			"redirect_uris": []string{"https://client.example/callback"}, "application_type": "web", "token_endpoint_auth_method": "none",
		})
		return cimdFetchResult{Status: 200, ContentType: "application/json", Body: body}, nil
	}
	if _, err := resolver.Resolve(context.Background(), "https://client.example/meta"); err == nil {
		t.Fatal("CIMD with mismatched client_id was accepted")
	}

	resolver = testClientResolver()
	resolver.lookupIP = publicLookup
	resolver.fetchDocument = func(context.Context, string, net.IPAddr) (cimdFetchResult, error) {
		return cimdFetchResult{Status: 200, ContentType: "text/html", Body: []byte(`{"client_id":"https://client.example/meta"}`)}, nil
	}
	if _, err := resolver.Resolve(context.Background(), "https://client.example/meta"); err == nil {
		t.Fatal("non-JSON CIMD response was accepted")
	}
}

func TestCIMDUsesBoundedCache(t *testing.T) {
	resolver := testClientResolver()
	resolver.lookupIP = publicLookup
	base := time.Unix(1_800_000_000, 0)
	resolver.now = func() time.Time { return base }
	fetches := 0
	resolver.fetchDocument = func(_ context.Context, clientID string, _ net.IPAddr) (cimdFetchResult, error) {
		fetches++
		body, _ := json.Marshal(map[string]any{
			"client_id": clientID, "client_name": "Cached Client",
			"redirect_uris": []string{"https://client.example/callback"},
			"grant_types":   []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
			"token_endpoint_auth_method": "none", "application_type": "web",
		})
		return cimdFetchResult{Status: 200, ContentType: "application/json", CacheControl: "public, max-age=60", Body: body}, nil
	}
	clientID := "https://client.example/meta"
	first, err := resolver.Resolve(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.Resolve(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if first.ClientID != clientID || second.ClientName != "Cached Client" || fetches != 1 {
		t.Fatalf("first=%+v second=%+v fetches=%d", first, second, fetches)
	}
}

func publicLookup(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
}
