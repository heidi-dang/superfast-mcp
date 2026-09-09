package edgecheck

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	defaultChatGPTRedirect = "https://chatgpt.com/connector_platform_oauth_redirect"
	managedMetadataPath    = "/.well-known/cloudflare-access-protected-resource/mcp"
	defaultTimeout         = 10 * time.Second
	maxMetadataBody        = 256 * 1024
	maxProtocolBody        = 1024 * 1024
)

var defaultExpectedTools = []string{
	"ping",
	"read_file",
	"write_file",
	"list_dir",
	"run_command",
	"git_status",
	"git_diff",
	"git_log",
}

type Options struct {
	MCPURL          string
	ChatGPTRedirect string
	ExpectedTools   []string
	AccessToken     string
	Timeout         time.Duration
}

type Result struct {
	AuthMode          string
	AuthorizationHost string
	ToolCount         int
}

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

type authorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

type registrationResponse struct {
	ClientID        string   `json:"client_id"`
	RedirectURIs    []string `json:"redirect_uris"`
	ApplicationType string   `json:"application_type"`
}

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func Check(ctx context.Context, client *http.Client, opts Options) (Result, error) {
	mcpURL, err := absoluteURL("MCP URL", strings.TrimSpace(opts.MCPURL), false)
	if err != nil {
		return Result{}, err
	}
	if opts.ChatGPTRedirect == "" {
		opts.ChatGPTRedirect = defaultChatGPTRedirect
	}
	if _, err := absoluteURL("ChatGPT redirect", opts.ChatGPTRedirect, true); err != nil {
		return Result{}, err
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if len(opts.ExpectedTools) == 0 {
		opts.ExpectedTools = append([]string(nil), defaultExpectedTools...)
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	client = boundedClient(client, opts.Timeout)

	challengeResp, err := doMCP(ctx, client, opts.MCPURL, "server/discover", "", 1)
	if err != nil {
		return Result{}, fmt.Errorf("edgecheck server/discover challenge request: %w", err)
	}
	challengeBody, readErr := readBounded(challengeResp.Body, maxProtocolBody)
	challengeResp.Body.Close()
	if readErr != nil {
		return Result{}, fmt.Errorf("edgecheck server/discover challenge response: %w", readErr)
	}
	if challengeResp.StatusCode != http.StatusUnauthorized {
		return Result{}, responseError("server/discover challenge", challengeResp, challengeBody)
	}

	metadataRaw, err := resourceMetadataFromChallenge(challengeResp.Header.Get("WWW-Authenticate"))
	if err != nil {
		return Result{}, err
	}
	metadataURL, err := absoluteURL("resource_metadata", metadataRaw, mcpURL.Scheme == "https")
	if err != nil {
		return Result{}, err
	}
	if metadataURL.Path != managedMetadataPath {
		return Result{}, fmt.Errorf("resource_metadata path %q is not Cloudflare managed path %q", metadataURL.Path, managedMetadataPath)
	}

	var protectedMetadata protectedResourceMetadata
	if err := fetchJSON(ctx, client, metadataURL.String(), "protected-resource metadata", &protectedMetadata); err != nil {
		return Result{}, err
	}
	if protectedMetadata.Resource != opts.MCPURL {
		return Result{}, fmt.Errorf("protected-resource metadata resource mismatch")
	}
	if len(protectedMetadata.AuthorizationServers) == 0 {
		return Result{}, fmt.Errorf("protected-resource metadata has no authorization server")
	}
	authorizationServer := strings.TrimSpace(protectedMetadata.AuthorizationServers[0])
	authorizationServerURL, err := absoluteURL("authorization server", authorizationServer, true)
	if err != nil {
		return Result{}, err
	}

	authorizationMetadataURL := strings.TrimRight(authorizationServer, "/") + "/.well-known/oauth-authorization-server"
	var authMetadata authorizationServerMetadata
	if err := fetchJSON(ctx, client, authorizationMetadataURL, "authorization-server metadata", &authMetadata); err != nil {
		return Result{}, err
	}
	if authMetadata.Issuer != authorizationServer {
		return Result{}, fmt.Errorf("authorization-server metadata issuer does not match advertised server")
	}
	if _, err := absoluteURL("authorization endpoint", authMetadata.AuthorizationEndpoint, true); err != nil {
		return Result{}, err
	}
	if _, err := absoluteURL("token endpoint", authMetadata.TokenEndpoint, true); err != nil {
		return Result{}, err
	}
	if _, err := absoluteURL("registration endpoint", authMetadata.RegistrationEndpoint, true); err != nil {
		return Result{}, err
	}
	if !slices.Contains(authMetadata.CodeChallengeMethodsSupported, "S256") {
		return Result{}, fmt.Errorf("authorization server does not support PKCE S256")
	}
	if !slices.Contains(authMetadata.GrantTypesSupported, "authorization_code") {
		return Result{}, fmt.Errorf("authorization server does not support authorization_code")
	}
	if !slices.Contains(authMetadata.GrantTypesSupported, "refresh_token") {
		return Result{}, fmt.Errorf("authorization server does not support refresh_token")
	}
	if !slices.Contains(authMetadata.TokenEndpointAuthMethodsSupported, "none") {
		return Result{}, fmt.Errorf("authorization server does not support public-client token auth none")
	}

	if err := probeInvalidRefreshToken(ctx, client, authMetadata.TokenEndpoint); err != nil {
		return Result{}, err
	}
	clientID, err := registerChatGPTClient(ctx, client, authMetadata.RegistrationEndpoint, opts.ChatGPTRedirect)
	if err != nil {
		return Result{}, err
	}
	if err := probeAuthorization(ctx, client, authMetadata.AuthorizationEndpoint, clientID, opts.ChatGPTRedirect, opts.MCPURL); err != nil {
		return Result{}, err
	}

	result := Result{
		AuthMode:          "cloudflare-managed",
		AuthorizationHost: authorizationServerURL.Host,
		ToolCount:         -1,
	}
	if strings.TrimSpace(opts.AccessToken) != "" {
		if _, err := callMCP(ctx, client, opts.MCPURL, "server/discover", opts.AccessToken, 10); err != nil {
			return Result{}, err
		}
		toolsEnvelope, err := callMCP(ctx, client, opts.MCPURL, "tools/list", opts.AccessToken, 11)
		if err != nil {
			return Result{}, err
		}
		var toolsResult struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(toolsEnvelope.Result, &toolsResult); err != nil {
			return Result{}, fmt.Errorf("authenticated tools/list returned invalid result JSON")
		}
		actualTools := make([]string, 0, len(toolsResult.Tools))
		for _, tool := range toolsResult.Tools {
			actualTools = append(actualTools, tool.Name)
		}
		if !sameToolSet(actualTools, opts.ExpectedTools) {
			return Result{}, fmt.Errorf("authenticated tools/list tool set mismatch: got=%d want=%d", len(actualTools), len(opts.ExpectedTools))
		}
		result.ToolCount = len(actualTools)
	}
	return result, nil
}

func boundedClient(client *http.Client, timeout time.Duration) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	if clone.Timeout <= 0 || clone.Timeout > timeout {
		clone.Timeout = timeout
	}
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

func absoluteURL(name, raw string, requireHTTPS bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute URL", name)
	}
	if requireHTTPS && u.Scheme != "https" {
		return nil, fmt.Errorf("%s must use HTTPS", name)
	}
	return u, nil
}

func resourceMetadataFromChallenge(header string) (string, error) {
	lower := strings.ToLower(header)
	const key = "resource_metadata="
	idx := strings.Index(lower, key)
	if idx < 0 {
		return "", fmt.Errorf("WWW-Authenticate challenge is missing resource_metadata")
	}
	rest := strings.TrimSpace(header[idx+len(key):])
	if rest == "" {
		return "", fmt.Errorf("WWW-Authenticate resource_metadata is empty")
	}
	if rest[0] == '"' {
		rest = rest[1:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return "", fmt.Errorf("WWW-Authenticate resource_metadata has an unterminated quote")
		}
		return rest[:end], nil
	}
	if end := strings.IndexAny(rest, ", \t"); end >= 0 {
		rest = rest[:end]
	}
	if rest == "" {
		return "", fmt.Errorf("WWW-Authenticate resource_metadata is empty")
	}
	return rest, nil
}

func fetchJSON(ctx context.Context, client *http.Client, endpoint, stage string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%s request setup failed", stage)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", stage, err)
	}
	body, readErr := readBounded(resp.Body, maxMetadataBody)
	resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("%s response read failed: %w", stage, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return responseError(stage, resp, body)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("%s returned invalid JSON", stage)
	}
	return nil
}

func probeInvalidRefreshToken(ctx context.Context, client *http.Client, endpoint string) error {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"superfast-edgecheck-intentionally-invalid"},
		"client_id":     {"superfast-edgecheck-intentionally-invalid"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("token probe request setup failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("token probe request failed: %w", err)
	}
	body, readErr := readBounded(resp.Body, maxMetadataBody)
	resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("token probe response read failed: %w", readErr)
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return responseError("token probe", resp, body)
	}
	if classifyBody(resp.Header.Get("Content-Type"), body) != "json" {
		return responseError("token probe", resp, body)
	}
	var oauthError struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &oauthError); err != nil || oauthError.Error == "" {
		return fmt.Errorf("token probe did not return structured OAuth JSON")
	}
	return nil
}

func registerChatGPTClient(ctx context.Context, client *http.Client, endpoint, redirect string) (string, error) {
	registration := struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ApplicationType         string   `json:"application_type"`
	}{
		ClientName:              "ChatGPT",
		RedirectURIs:            []string{redirect},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		ApplicationType:         "web",
	}
	body, err := json.Marshal(registration)
	if err != nil {
		return "", fmt.Errorf("DCR request encoding failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("DCR request setup failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DCR request failed: %w", err)
	}
	responseBody, readErr := readBounded(resp.Body, maxMetadataBody)
	resp.Body.Close()
	if readErr != nil {
		return "", fmt.Errorf("DCR response read failed: %w", readErr)
	}
	if resp.StatusCode != http.StatusCreated {
		return "", responseError("DCR", resp, responseBody)
	}
	var registered registrationResponse
	if err := json.Unmarshal(responseBody, &registered); err != nil {
		return "", fmt.Errorf("DCR returned invalid JSON")
	}
	if registered.ClientID == "" {
		return "", fmt.Errorf("DCR response omitted client_id")
	}
	if len(registered.RedirectURIs) != 1 || registered.RedirectURIs[0] != redirect {
		return "", fmt.Errorf("DCR returned redirect URI mutation")
	}
	if registered.ApplicationType != "web" {
		return "", fmt.Errorf("DCR returned application type %q, want web", registered.ApplicationType)
	}
	return registered.ClientID, nil
}

func probeAuthorization(ctx context.Context, client *http.Client, endpoint, clientID, redirect, resource string) error {
	verifier := strings.Repeat("v", 64)
	challengeBytes := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challengeBytes[:])},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
		"scope":                 {"mcp"},
		"state":                 {"superfast-edgecheck"},
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("authorization probe endpoint is invalid")
	}
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("authorization probe request setup failed")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("authorization probe request failed: %w", err)
	}
	body, readErr := readBounded(resp.Body, maxMetadataBody)
	resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("authorization probe response read failed: %w", readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return responseError("authorization probe", resp, body)
	}
	if location := resp.Header.Get("Location"); location != "" {
		redirected, err := url.Parse(location)
		if err != nil {
			return fmt.Errorf("authorization probe returned invalid redirect")
		}
		if redirected.Query().Get("error") != "" {
			return fmt.Errorf("authorization probe returned OAuth error")
		}
	}
	if classifyBody(resp.Header.Get("Content-Type"), body) == "json" {
		var oauthError struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &oauthError) == nil && oauthError.Error != "" {
			return fmt.Errorf("authorization probe returned OAuth error")
		}
	}
	return nil
}

func doMCP(ctx context.Context, client *http.Client, endpoint, method, accessToken string, id int) (*http.Response, error) {
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  map[string]any{},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	return client.Do(req)
}

func callMCP(ctx context.Context, client *http.Client, endpoint, method, accessToken string, id int) (rpcEnvelope, error) {
	resp, err := doMCP(ctx, client, endpoint, method, accessToken, id)
	if err != nil {
		return rpcEnvelope{}, fmt.Errorf("authenticated MCP %s request failed: %w", method, err)
	}
	body, readErr := readBounded(resp.Body, maxProtocolBody)
	resp.Body.Close()
	if readErr != nil {
		return rpcEnvelope{}, fmt.Errorf("authenticated MCP %s response read failed: %w", method, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return rpcEnvelope{}, responseError("authenticated MCP "+method, resp, body)
	}
	envelope, err := decodeRPCEnvelope(resp.Header.Get("Content-Type"), body)
	if err != nil {
		return rpcEnvelope{}, fmt.Errorf("authenticated MCP %s returned invalid protocol response", method)
	}
	if len(envelope.Error) != 0 && string(envelope.Error) != "null" {
		return rpcEnvelope{}, fmt.Errorf("authenticated MCP %s returned JSON-RPC error", method)
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return rpcEnvelope{}, fmt.Errorf("authenticated MCP %s omitted result", method)
	}
	return envelope, nil
}

func decodeRPCEnvelope(contentType string, body []byte) (rpcEnvelope, error) {
	var envelope rpcEnvelope
	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		if err := json.Unmarshal(body, &envelope); err != nil {
			return rpcEnvelope{}, err
		}
		return envelope, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maxProtocolBody)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if json.Unmarshal([]byte(payload), &envelope) == nil {
			return envelope, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return rpcEnvelope{}, err
	}
	return rpcEnvelope{}, fmt.Errorf("no JSON-RPC event")
}

func sameToolSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualSet := make(map[string]struct{}, len(actual))
	for _, name := range actual {
		if name == "" {
			return false
		}
		if _, duplicate := actualSet[name]; duplicate {
			return false
		}
		actualSet[name] = struct{}{}
	}
	for _, name := range expected {
		if _, ok := actualSet[name]; !ok {
			return false
		}
	}
	return true
}

func readBounded(body io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(body, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeded %d bytes", limit)
	}
	return data, nil
}

func responseError(stage string, resp *http.Response, body []byte) error {
	return fmt.Errorf("%s: status=%d content_type=%q body=%s cf_ray=%q",
		stage,
		resp.StatusCode,
		resp.Header.Get("Content-Type"),
		classifyBody(resp.Header.Get("Content-Type"), body),
		resp.Header.Get("Cf-Ray"),
	)
}

func classifyBody(contentType string, body []byte) string {
	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "json") {
		return "json"
	}
	if strings.Contains(contentType, "html") {
		return "html"
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return "json"
	}
	if bytes.HasPrefix(bytes.ToLower(trimmed), []byte("<!doctype html")) || bytes.HasPrefix(bytes.ToLower(trimmed), []byte("<html")) {
		return "html"
	}
	return "text"
}
