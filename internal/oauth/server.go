package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const (
	ownerPasswordLabel = "superfast-mcp/oauth-owner/v1"
	signingKeyLabel    = "superfast-mcp/oauth-signing/v1"
	clientPrefix       = "sfc1"
	accessPrefix       = "sfa1"
	refreshPrefix      = "sfr1"
	accessTTL          = time.Hour
	refreshTTL         = 30 * 24 * time.Hour
	codeTTL            = 5 * time.Minute
)

var authorizationPage = template.Must(template.New("authorize").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize superfast-mcp</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0b0d10;color:#e8eef7;margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}main{width:min(460px,100%);background:#15181e;border:1px solid #2a303a;border-radius:16px;padding:28px;box-sizing:border-box}h1{font-size:22px;margin:0 0 12px}p{color:#aab3c2;line-height:1.5}.client{color:#fff;font-weight:600}.error{color:#ff8a80}label{display:block;margin:22px 0 8px;font-size:14px}input{width:100%;box-sizing:border-box;border:1px solid #3a4250;border-radius:10px;background:#0d1015;color:#fff;padding:12px;font:inherit}button{margin-top:16px;width:100%;border:0;border-radius:10px;padding:12px 16px;font:inherit;font-weight:700;background:#fff;color:#111;cursor:pointer}.scope{font-family:ui-monospace,monospace;font-size:12px;color:#8e99ab}</style>
</head>
<body><main>
<h1>Authorize superfast-mcp</h1>
<p><span class="client">{{.ClientName}}</span> is requesting access to this private MCP server.</p>
<p class="scope">Scope: {{.Scope}}</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}" autocomplete="off">
<label for="owner_password">Owner authorization password</label>
<input id="owner_password" name="owner_password" type="password" required autofocus autocomplete="current-password">
<button type="submit">Authorize</button>
</form>
</main></body></html>`))

type Server struct {
	issuer        string
	resource      string
	ownerPassword string
	signingKey    []byte

	mu    sync.Mutex
	codes map[string]authorizationGrant
	now   func() time.Time
}

type clientRecord struct {
	Version      int      `json:"v"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
	Application  string   `json:"application_type,omitempty"`
	IssuedAt     int64    `json:"iat"`
}

type authorizationGrant struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	Scope         string
	ExpiresAt     time.Time
}

type tokenClaims struct {
	Version  int    `json:"v"`
	Use      string `json:"use"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	JTI      string `json:"jti"`
}

type authorizationRequest struct {
	ClientID      string
	Client        clientRecord
	RedirectURI   string
	CodeChallenge string
	State         string
	Resource      string
	Scope         string
}

type authorizationPageData struct {
	ClientName string
	Scope      string
	Action     string
	Error      string
}

func New(issuer, resource, masterToken, ownerPassword string) (*Server, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	resource = strings.TrimSpace(resource)
	masterToken = strings.TrimSpace(masterToken)
	ownerPassword = strings.TrimSpace(ownerPassword)
	if issuer == "" || resource == "" {
		return nil, fmt.Errorf("OAuth issuer and resource are required")
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" {
		return nil, fmt.Errorf("OAuth issuer must be an absolute HTTPS URL")
	}
	resourceURL, err := url.Parse(resource)
	if err != nil || resourceURL.Scheme != "https" || resourceURL.Host == "" {
		return nil, fmt.Errorf("OAuth resource must be an absolute HTTPS URL")
	}
	if masterToken == "" {
		return nil, fmt.Errorf("OAuth master token is required")
	}
	if ownerPassword == "" {
		ownerPassword = OwnerPasswordFromToken(masterToken)
	}
	return &Server{
		issuer:        issuer,
		resource:      resource,
		ownerPassword: ownerPassword,
		signingKey:    derive(masterToken, signingKeyLabel),
		codes:         make(map[string]authorizationGrant),
		now:           time.Now,
	}, nil
}

func OwnerPasswordFromToken(masterToken string) string {
	return hex.EncodeToString(derive(masterToken, ownerPasswordLabel))
}

func derive(masterToken, label string) []byte {
	mac := hmac.New(sha256.New, []byte(masterToken))
	_, _ = mac.Write([]byte(label))
	return mac.Sum(nil)
}

func (s *Server) ResourceMetadataURL() string {
	return s.issuer + "/.well-known/oauth-protected-resource/mcp"
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	metadata := &oauthex.ProtectedResourceMetadata{
		Resource:               s.resource,
		AuthorizationServers:   []string{s.issuer},
		ScopesSupported:        []string{"mcp"},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "superfast-mcp",
	}
	metadataHandler := mcpauth.ProtectedResourceMetadataHandler(metadata)
	mux.Handle("/.well-known/oauth-protected-resource", metadataHandler)
	mux.Handle("/.well-known/oauth-protected-resource/mcp", metadataHandler)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
}

func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.issuer,
		"authorization_endpoint":                         s.issuer + "/authorize",
		"token_endpoint":                                 s.issuer + "/token",
		"registration_endpoint":                          s.issuer + "/register",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"scopes_supported":                               []string{"mcp", "offline_access"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	defer r.Body.Close()
	var meta oauthex.ClientRegistrationMetadata
	if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid client registration document")
		return
	}
	if err := normalizeClientMetadata(&meta); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
		return
	}

	client := clientRecord{
		Version:      1,
		RedirectURIs: append([]string(nil), meta.RedirectURIs...),
		ClientName:   meta.ClientName,
		Application:  meta.ApplicationType,
		IssuedAt:     s.now().Unix(),
	}
	clientID, err := s.sign(clientPrefix, client)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to register client")
		return
	}
	writeJSONStatus(w, http.StatusCreated, struct {
		oauthex.ClientRegistrationMetadata
		ClientID         string `json:"client_id"`
		ClientIDIssuedAt int64  `json:"client_id_issued_at"`
	}{
		ClientRegistrationMetadata: meta,
		ClientID:                   clientID,
		ClientIDIssuedAt:           client.IssuedAt,
	})
}

func normalizeClientMetadata(meta *oauthex.ClientRegistrationMetadata) error {
	if len(meta.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris is required")
	}
	for _, redirect := range meta.RedirectURIs {
		if err := validateRedirectURI(redirect); err != nil {
			return err
		}
	}
	if meta.TokenEndpointAuthMethod == "" {
		meta.TokenEndpointAuthMethod = "none"
	}
	if meta.TokenEndpointAuthMethod != "none" {
		return fmt.Errorf("only public clients using token_endpoint_auth_method=none are supported")
	}
	if len(meta.GrantTypes) == 0 {
		meta.GrantTypes = []string{"authorization_code"}
	}
	for _, grantType := range meta.GrantTypes {
		if grantType != "authorization_code" && grantType != "refresh_token" {
			return fmt.Errorf("unsupported grant_type %q", grantType)
		}
	}
	if !slices.Contains(meta.GrantTypes, "authorization_code") {
		return fmt.Errorf("authorization_code grant is required")
	}
	if len(meta.ResponseTypes) == 0 {
		meta.ResponseTypes = []string{"code"}
	}
	if len(meta.ResponseTypes) != 1 || meta.ResponseTypes[0] != "code" {
		return fmt.Errorf("only response_type=code is supported")
	}
	if meta.ApplicationType == "" {
		meta.ApplicationType = "web"
	}
	if meta.ApplicationType != "web" && meta.ApplicationType != "native" {
		return fmt.Errorf("application_type must be web or native")
	}
	return nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("invalid redirect URI %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("redirect URI %q must use HTTPS or HTTP loopback", raw)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request, err := s.validateAuthorizationRequest(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		s.renderAuthorizationPage(w, r, request, "", http.StatusOK)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		s.renderAuthorizationPage(w, r, request, "Invalid authorization request.", http.StatusBadRequest)
		return
	}
	password := r.PostForm.Get("owner_password")
	if subtle.ConstantTimeCompare([]byte(password), []byte(s.ownerPassword)) != 1 {
		s.renderAuthorizationPage(w, r, request, "Invalid owner authorization password.", http.StatusUnauthorized)
		return
	}

	code, err := randomToken(32)
	if err != nil {
		http.Error(w, "authorization failed", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.codes[code] = authorizationGrant{
		ClientID:      request.ClientID,
		RedirectURI:   request.RedirectURI,
		CodeChallenge: request.CodeChallenge,
		Resource:      request.Resource,
		Scope:         request.Scope,
		ExpiresAt:     s.now().Add(codeTTL),
	}
	s.mu.Unlock()

	redirect, _ := url.Parse(request.RedirectURI)
	query := redirect.Query()
	query.Set("code", code)
	if request.State != "" {
		query.Set("state", request.State)
	}
	query.Set("iss", s.issuer)
	redirect.RawQuery = query.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func (s *Server) renderAuthorizationPage(w http.ResponseWriter, r *http.Request, request *authorizationRequest, errorMessage string, status int) {
	clientName := strings.TrimSpace(request.Client.ClientName)
	if clientName == "" {
		clientName = "OAuth client"
	}
	action := "/authorize"
	if r.URL.RawQuery != "" {
		action += "?" + r.URL.RawQuery
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; style-src 'unsafe-inline'; form-action 'self' %s; frame-ancestors 'none'; base-uri 'none'", s.issuer))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_ = authorizationPage.Execute(w, authorizationPageData{ClientName: clientName, Scope: request.Scope, Action: action, Error: errorMessage})
}

func (s *Server) validateAuthorizationRequest(values url.Values) (*authorizationRequest, error) {
	if values.Get("response_type") != "code" {
		return nil, fmt.Errorf("response_type must be code")
	}
	clientID := values.Get("client_id")
	client, err := s.parseClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client_id")
	}
	redirectURI := values.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		return nil, fmt.Errorf("redirect_uri does not match registered client")
	}
	challenge := values.Get("code_challenge")
	if challenge == "" || values.Get("code_challenge_method") != "S256" {
		return nil, fmt.Errorf("PKCE S256 code_challenge is required")
	}
	resource := values.Get("resource")
	if resource == "" {
		resource = s.resource
	}
	if resource != s.resource {
		return nil, fmt.Errorf("invalid OAuth resource")
	}
	scope, err := normalizeScope(values.Get("scope"))
	if err != nil {
		return nil, err
	}
	return &authorizationRequest{
		ClientID:      clientID,
		Client:        client,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		State:         values.Get("state"),
		Resource:      resource,
		Scope:         scope,
	}, nil
}

func normalizeScope(scope string) (string, error) {
	if strings.TrimSpace(scope) == "" {
		return "mcp offline_access", nil
	}
	fields := strings.Fields(scope)
	for _, value := range fields {
		if value != "mcp" && value != "offline_access" {
			return "", fmt.Errorf("unsupported scope %q", value)
		}
	}
	if !slices.Contains(fields, "mcp") {
		return "", fmt.Errorf("mcp scope is required")
	}
	return strings.Join(fields, " "), nil
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.exchangeAuthorizationCode(w, r)
	case "refresh_token":
		s.exchangeRefreshToken(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) exchangeAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	clientID := r.PostForm.Get("client_id")
	if _, err := s.parseClient(clientID); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "invalid client_id")
		return
	}
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	if code == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code and code_verifier are required")
		return
	}

	s.mu.Lock()
	grant, ok := s.codes[code]
	if ok {
		resource := r.PostForm.Get("resource")
		if resource == "" {
			resource = grant.Resource
		}
		challengeBytes := sha256.Sum256([]byte(verifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
		valid := grant.ClientID == clientID &&
			grant.RedirectURI == r.PostForm.Get("redirect_uri") &&
			grant.Resource == resource &&
			grant.ExpiresAt.After(s.now()) &&
			subtle.ConstantTimeCompare([]byte(grant.CodeChallenge), []byte(computedChallenge)) == 1
		if valid {
			delete(s.codes, code)
		} else {
			ok = false
		}
	}
	s.mu.Unlock()
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}
	s.issueTokens(w, clientID, grant.Scope, grant.Resource)
}

func (s *Server) exchangeRefreshToken(w http.ResponseWriter, r *http.Request) {
	clientID := r.PostForm.Get("client_id")
	if _, err := s.parseClient(clientID); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "invalid client_id")
		return
	}
	claims, err := s.parseToken(refreshPrefix, r.PostForm.Get("refresh_token"))
	if err != nil || claims.Use != "refresh" || claims.ClientID != clientID || claims.Expires <= s.now().Unix() {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}
	resource := r.PostForm.Get("resource")
	if resource == "" {
		resource = claims.Audience
	}
	if resource != s.resource || claims.Audience != s.resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "invalid OAuth resource")
		return
	}
	s.issueTokens(w, clientID, claims.Scope, resource)
}

func (s *Server) issueTokens(w http.ResponseWriter, clientID, scope, resource string) {
	now := s.now()
	access, err := s.mintToken(accessPrefix, "access", clientID, scope, resource, now.Add(accessTTL))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue access token")
		return
	}
	response := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(accessTTL.Seconds()),
		"scope":        scope,
	}
	if slices.Contains(strings.Fields(scope), "offline_access") {
		refresh, err := s.mintToken(refreshPrefix, "refresh", clientID, scope, resource, now.Add(refreshTTL))
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue refresh token")
			return
		}
		response["refresh_token"] = refresh
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) mintToken(prefix, use, clientID, scope, resource string, expires time.Time) (string, error) {
	jti, err := randomToken(16)
	if err != nil {
		return "", err
	}
	return s.sign(prefix, tokenClaims{
		Version:  1,
		Use:      use,
		Issuer:   s.issuer,
		Audience: resource,
		Subject:  "owner",
		ClientID: clientID,
		Scope:    scope,
		IssuedAt: s.now().Unix(),
		Expires:  expires.Unix(),
		JTI:      jti,
	})
}

func (s *Server) VerifyAccessToken(token string) bool {
	claims, err := s.parseToken(accessPrefix, token)
	if err != nil {
		return false
	}
	return claims.Version == 1 &&
		claims.Use == "access" &&
		claims.Issuer == s.issuer &&
		claims.Audience == s.resource &&
		claims.Subject == "owner" &&
		claims.Expires > s.now().Unix() &&
		claims.IssuedAt <= s.now().Add(time.Minute).Unix() &&
		slices.Contains(strings.Fields(claims.Scope), "mcp")
}

func (s *Server) parseToken(prefix, token string) (tokenClaims, error) {
	var claims tokenClaims
	if err := s.verify(prefix, token, &claims); err != nil {
		return tokenClaims{}, err
	}
	if claims.Issuer != s.issuer || claims.Audience != s.resource {
		return tokenClaims{}, fmt.Errorf("token target mismatch")
	}
	return claims, nil
}

func (s *Server) parseClient(clientID string) (clientRecord, error) {
	var client clientRecord
	if err := s.verify(clientPrefix, clientID, &client); err != nil {
		return clientRecord{}, err
	}
	if client.Version != 1 || len(client.RedirectURIs) == 0 {
		return clientRecord{}, fmt.Errorf("invalid client")
	}
	return client, nil
}

func (s *Server) sign(prefix string, value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = io.WriteString(mac, prefix+"."+encoded)
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return prefix + "." + encoded + "." + signature, nil
}

func (s *Server) verify(prefix, token string, target any) error {
	if len(token) == 0 || len(token) > 16*1024 {
		return fmt.Errorf("invalid token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != prefix {
		return fmt.Errorf("invalid token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid token")
	}
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = io.WriteString(mac, parts[0]+"."+parts[1])
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return fmt.Errorf("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid token")
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSONStatus(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	writeJSONStatus(w, status, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
