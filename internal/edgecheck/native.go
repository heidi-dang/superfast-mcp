package edgecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type NativeOptions struct {
	Origin          string
	Resource        string
	ChatGPTRedirect string
	Timeout         time.Duration
}

type NativeResult struct {
	Issuer               string
	DCRApplicationType   string
	RevocationAdvertised bool
	CIMDSupported        bool
}

type nativeAuthorizationMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported"`
	ProtectedResources                []string `json:"protected_resources"`
}

func CheckNative(ctx context.Context, client *http.Client, opts NativeOptions) (NativeResult, error) {
	originURL, err := absoluteURL("native origin", strings.TrimSpace(opts.Origin), true)
	if err != nil {
		return NativeResult{}, err
	}
	origin := strings.TrimRight(originURL.String(), "/")
	resource := strings.TrimSpace(opts.Resource)
	if resource == "" {
		resource = origin + "/mcp"
	}
	if _, err := absoluteURL("native resource", resource, true); err != nil {
		return NativeResult{}, err
	}
	redirect := strings.TrimSpace(opts.ChatGPTRedirect)
	if redirect == "" {
		redirect = defaultChatGPTRedirect
	}
	if _, err := absoluteURL("ChatGPT redirect", redirect, true); err != nil {
		return NativeResult{}, err
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	client = boundedClient(client, opts.Timeout)

	var protected protectedResourceMetadata
	if err := fetchJSON(ctx, client, origin+"/.well-known/oauth-protected-resource/mcp", "native protected-resource metadata", &protected); err != nil {
		return NativeResult{}, err
	}
	if protected.Resource != resource || len(protected.AuthorizationServers) != 1 || strings.TrimRight(protected.AuthorizationServers[0], "/") != origin {
		return NativeResult{}, fmt.Errorf("native protected-resource metadata mismatch")
	}

	var metadata nativeAuthorizationMetadata
	if err := fetchJSON(ctx, client, origin+"/.well-known/oauth-authorization-server", "native authorization-server metadata", &metadata); err != nil {
		return NativeResult{}, err
	}
	if strings.TrimRight(metadata.Issuer, "/") != origin {
		return NativeResult{}, fmt.Errorf("native issuer mismatch")
	}
	for label, endpoint := range map[string]string{
		"authorization_endpoint": metadata.AuthorizationEndpoint,
		"token_endpoint":         metadata.TokenEndpoint,
		"registration_endpoint":  metadata.RegistrationEndpoint,
		"revocation_endpoint":    metadata.RevocationEndpoint,
	} {
		u, err := absoluteURL(label, endpoint, true)
		if err != nil || u.Scheme+"://"+u.Host != originURL.Scheme+"://"+originURL.Host {
			return NativeResult{}, fmt.Errorf("native %s is not on issuer origin", label)
		}
	}
	if !slices.Contains(metadata.ResponseTypesSupported, "code") || !slices.Contains(metadata.ResponseModesSupported, "query") ||
		!slices.Contains(metadata.GrantTypesSupported, "authorization_code") || !slices.Contains(metadata.GrantTypesSupported, "refresh_token") ||
		!slices.Contains(metadata.TokenEndpointAuthMethodsSupported, "none") || !slices.Contains(metadata.CodeChallengeMethodsSupported, "S256") ||
		!metadata.ClientIDMetadataDocumentSupported || !slices.Contains(metadata.ProtectedResources, resource) {
		return NativeResult{}, fmt.Errorf("native authorization metadata is missing AWS-parity capabilities")
	}
	if err := probeInvalidRefreshToken(ctx, client, metadata.TokenEndpoint); err != nil {
		return NativeResult{}, err
	}
	clientID, appType, err := registerNativeChatGPTClient(ctx, client, metadata.RegistrationEndpoint, redirect)
	if err != nil {
		return NativeResult{}, err
	}
	if err := probeNativeAuthorization(ctx, client, metadata.AuthorizationEndpoint, clientID, redirect, resource, origin); err != nil {
		return NativeResult{}, err
	}
	if err := probeNativeRevocation(ctx, client, metadata.RevocationEndpoint); err != nil {
		return NativeResult{}, err
	}
	return NativeResult{Issuer: metadata.Issuer, DCRApplicationType: appType, RevocationAdvertised: metadata.RevocationEndpoint != "", CIMDSupported: metadata.ClientIDMetadataDocumentSupported}, nil
}

func registerNativeChatGPTClient(ctx context.Context, client *http.Client, endpoint, redirect string) (string, string, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name": "ChatGPT", "redirect_uris": []string{redirect},
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "none", "application_type": "web",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("native DCR request setup failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("native DCR request failed: %w", err)
	}
	responseBody, readErr := readBounded(resp.Body, maxMetadataBody)
	resp.Body.Close()
	if readErr != nil {
		return "", "", readErr
	}
	if resp.StatusCode != http.StatusCreated {
		return "", "", responseError("native DCR", resp, responseBody)
	}
	var registered registrationResponse
	if json.Unmarshal(responseBody, &registered) != nil || registered.ClientID == "" {
		return "", "", fmt.Errorf("native DCR returned invalid JSON")
	}
	if len(registered.RedirectURIs) != 1 || registered.RedirectURIs[0] != redirect || registered.ApplicationType != "web" {
		return "", "", fmt.Errorf("native DCR did not preserve ChatGPT client metadata")
	}
	return registered.ClientID, registered.ApplicationType, nil
}

func probeNativeAuthorization(ctx context.Context, client *http.Client, endpoint, clientID, redirect, resource, origin string) error {
	verifier := strings.Repeat("v", 64)
	challenge := PKCEForEdgecheck(verifier)
	u, _ := url.Parse(endpoint)
	u.RawQuery = url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "resource": {resource}, "scope": {"mcp"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"native-edgecheck"}}.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("native authorization probe failed: %w", err)
	}
	body, _ := readBounded(resp.Body, maxMetadataBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return responseError("native authorization probe", resp, body)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || strings.TrimRight(location.Scheme+"://"+location.Host, "/") != origin || location.Path != "/oauth/login" || location.Query().Get("ticket") == "" {
		return fmt.Errorf("native authorization did not redirect to signed login ticket")
	}
	return nil
}

func probeNativeRevocation(ctx context.Context, client *http.Client, endpoint string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(url.Values{"token": {"edgecheck-unknown-token"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("native revocation probe failed: %w", err)
	}
	body, _ := readBounded(resp.Body, maxMetadataBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || classifyBody(resp.Header.Get("Content-Type"), body) != "json" {
		return responseError("native revocation probe", resp, body)
	}
	return nil
}

func PKCEForEdgecheck(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
