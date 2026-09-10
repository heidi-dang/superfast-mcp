package oauth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultAccessTokenTTL       = 15 * time.Minute
	defaultGrantTTL             = 14 * 24 * time.Hour
	defaultAuthorizationCodeTTL = 5 * time.Minute
	maxOAuthBody                = 64 * 1024
)

var pkceVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

var consentPage = template.Must(template.New("oauth-consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Superfast</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 20px;color:#171717}main{border:1px solid #ddd;border-radius:14px;padding:24px}h1{font-size:22px;margin:0 0 14px}dl{display:grid;grid-template-columns:120px 1fr;gap:8px 12px}dt{font-weight:600}dd{margin:0;overflow-wrap:anywhere}.actions{display:flex;gap:10px;margin-top:22px}button{padding:10px 16px;border-radius:8px;border:1px solid #bbb;background:white;font-weight:600}button[value=approve]{background:#111;color:white;border-color:#111}.warning{margin-top:16px;padding:10px 12px;background:#fff7e6;border-radius:8px}</style></head>
<body><main><h1>Authorize Superfast</h1><p>An MCP client is requesting access to your Superfast server.</p>
<dl><dt>Client</dt><dd>{{.ClientName}}</dd><dt>Resource</dt><dd>{{.Resource}}</dd><dt>Scopes</dt><dd>{{.Scope}}</dd><dt>Redirect</dt><dd>{{.RedirectHost}}</dd></dl>
{{if .Loopback}}<div class="warning">This client redirects to a loopback address on this device. Approve only if you initiated the connection.</div>{{end}}
<form method="post" action="/oauth/login"><input type="hidden" name="ticket" value="{{.Ticket}}"><div class="actions"><button type="submit" name="decision" value="approve">Approve</button><button type="submit" name="decision" value="deny">Deny</button></div></form>
</main></body></html>`))

type Identity struct {
	Subject string
	Email   string
}

type ServerConfig struct {
	Issuer               string
	Resource             string
	Scopes               []string
	Secret               string
	StateDB              string
	AccessTokenTTL       time.Duration
	GrantTTL             time.Duration
	AuthorizationCodeTTL time.Duration
}

type Server struct {
	issuer               string
	resource             string
	scopes               []string
	secret               []byte
	state                *StateStore
	clients              *ClientResolver
	tokens               *TokenIssuer
	accessTokenTTL       time.Duration
	grantTTL             time.Duration
	authorizationCodeTTL time.Duration
	now                  func() time.Time
}

type authorizationRequest struct {
	ClientID      string
	Client        ClientMetadata
	RedirectURI   string
	CodeChallenge string
	Resource      string
	Scope         string
	State         string
}

type authorizationTicketClaims struct {
	Type          string `json:"typ"`
	ClientID      string `json:"client_id"`
	ClientName    string `json:"client_name"`
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge"`
	Resource      string `json:"resource"`
	Scope         string `json:"scope"`
	State         string `json:"state,omitempty"`
	jwt.RegisteredClaims
}

type consentData struct {
	Ticket       string
	ClientName   string
	Resource     string
	Scope        string
	RedirectHost string
	Loopback     bool
}

func New(cfg ServerConfig) (*Server, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	resource := strings.TrimSpace(cfg.Resource)
	if err := validateHTTPSURL(issuer, "native OAuth issuer"); err != nil {
		return nil, err
	}
	if err := validateHTTPSURL(resource, "native OAuth resource"); err != nil {
		return nil, err
	}
	secret := []byte(strings.TrimSpace(cfg.Secret))
	if len(secret) < 32 {
		return nil, errors.New("native OAuth secret must be at least 32 characters")
	}
	if strings.TrimSpace(cfg.StateDB) == "" {
		return nil, errors.New("native OAuth state database path is required")
	}
	scopes := normalizeSupportedScopes(cfg.Scopes)
	if len(scopes) == 0 {
		scopes = []string{"mcp"}
	}
	state, err := OpenStateStore(cfg.StateDB)
	if err != nil {
		return nil, err
	}
	tokens, err := NewTokenIssuer(issuer, resource, secret)
	if err != nil {
		_ = state.Close()
		return nil, err
	}
	accessTTL := cfg.AccessTokenTTL
	if accessTTL == 0 {
		accessTTL = defaultAccessTokenTTL
	}
	if accessTTL < time.Minute {
		accessTTL = time.Minute
	}
	grantTTL := cfg.GrantTTL
	if grantTTL == 0 {
		grantTTL = defaultGrantTTL
	}
	if grantTTL < accessTTL {
		grantTTL = accessTTL
	}
	codeTTL := cfg.AuthorizationCodeTTL
	if codeTTL == 0 {
		codeTTL = defaultAuthorizationCodeTTL
	}
	if codeTTL < 30*time.Second {
		codeTTL = 30 * time.Second
	}
	if codeTTL > 10*time.Minute {
		codeTTL = 10 * time.Minute
	}
	return &Server{
		issuer:               issuer,
		resource:             resource,
		scopes:               scopes,
		secret:               secret,
		state:                state,
		clients:              NewClientResolver(issuer, secret),
		tokens:               tokens,
		accessTokenTTL:       accessTTL,
		grantTTL:             grantTTL,
		authorizationCodeTTL: codeTTL,
		now:                  time.Now,
	}, nil
}

func normalizeSupportedScopes(scopes []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func validateHTTPSURL(raw, label string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute HTTPS URL", label)
	}
	return nil
}

func (s *Server) Close() error {
	if s == nil || s.state == nil {
		return nil
	}
	return s.state.Close()
}

func (s *Server) ResourceMetadataURL() string {
	return s.issuer + "/.well-known/oauth-protected-resource/mcp"
}

// RegisterProtocolRoutes registers both discovery metadata and operational
// OAuth endpoints. Prefer RegisterOperationalRoutes when Cloudflare Access
// owns public discovery after Managed OAuth cutover.
func (s *Server) RegisterProtocolRoutes(mux *http.ServeMux) {
	s.RegisterMetadataRoutes(mux)
	s.RegisterOperationalRoutes(mux)
}

// RegisterMetadataRoutes exposes the RFC 9728 / RFC 8414 well-known documents.
// Only call this when the deployment intentionally wants clients to discover
// the native authorization server (rollback / pure-native mode).
func (s *Server) RegisterMetadataRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", s.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
}

// RegisterOperationalRoutes registers the authorization, token, registration,
// and revocation endpoints required for a working native OAuth flow.
func (s *Server) RegisterOperationalRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/oauth/register", s.handleRegister)
	mux.HandleFunc("/oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/token", s.handleToken)
	mux.HandleFunc("/oauth/revoke", s.handleRevoke)
}

func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body := map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"bearer_methods_supported": []string{"header"},
	}
	if len(s.scopes) > 0 {
		body["scopes_supported"] = append([]string(nil), s.scopes...)
	}
	writeOAuthJSON(w, http.StatusOK, body)
}

func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body := map[string]any{
		"issuer":                                         s.issuer,
		"authorization_endpoint":                         s.issuer + "/oauth/authorize",
		"token_endpoint":                                 s.issuer + "/oauth/token",
		"registration_endpoint":                          s.issuer + "/oauth/register",
		"revocation_endpoint":                            s.issuer + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
		"protected_resources":                            []string{s.resource},
	}
	if len(s.scopes) > 0 {
		body["scopes_supported"] = append([]string(nil), s.scopes...)
	}
	writeOAuthJSON(w, http.StatusOK, body)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input ClientRegistrationInput
	if err := decodeBoundedJSON(w, r, &input); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid client registration document")
		return
	}
	clientID, metadata, issuedAt, err := s.clients.IssueDynamicClient(input)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	writeOAuthJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        issuedAt,
		"client_name":                metadata.ClientName,
		"redirect_uris":              metadata.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"application_type":           metadata.ApplicationType,
	})
}

func decodeBoundedJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	request, err := s.validateAuthorizationRequest(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ticket, err := s.signAuthorizationTicket(request)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to prepare authorization")
		return
	}
	location := s.issuer + "/oauth/login?ticket=" + url.QueryEscape(ticket)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

func (s *Server) validateAuthorizationRequest(r *http.Request) (*authorizationRequest, error) {
	values := r.URL.Query()
	if values.Get("response_type") != "code" {
		return nil, errors.New("response_type=code is required")
	}
	clientID := strings.TrimSpace(values.Get("client_id"))
	redirectRaw := strings.TrimSpace(values.Get("redirect_uri"))
	resource := strings.TrimSpace(values.Get("resource"))
	challenge := strings.TrimSpace(values.Get("code_challenge"))
	if clientID == "" || redirectRaw == "" || resource == "" || challenge == "" {
		return nil, errors.New("client_id, redirect_uri, resource, and code_challenge are required")
	}
	if values.Get("code_challenge_method") != "S256" {
		return nil, errors.New("code_challenge_method=S256 is required")
	}
	if resource != s.resource {
		return nil, errors.New("resource does not match this MCP server")
	}
	redirectURI, err := validateClientRedirectURI(redirectRaw)
	if err != nil {
		return nil, err
	}
	client, err := s.clients.Resolve(r.Context(), clientID)
	if err != nil {
		return nil, errors.New("unknown OAuth client_id")
	}
	if !containsString(client.RedirectURIs, redirectURI) {
		return nil, errors.New("redirect_uri is not registered for this client")
	}
	scope, err := s.requestedScope(values.Get("scope"))
	if err != nil {
		return nil, err
	}
	return &authorizationRequest{
		ClientID:      clientID,
		Client:        client,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		Resource:      resource,
		Scope:         scope,
		State:         values.Get("state"),
	}, nil
}

func (s *Server) requestedScope(raw string) (string, error) {
	requested := strings.Fields(raw)
	if len(requested) == 0 {
		requested = append([]string(nil), s.scopes...)
	}
	supported := make(map[string]struct{}, len(s.scopes))
	for _, scope := range s.scopes {
		supported[scope] = struct{}{}
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(requested))
	for _, scope := range requested {
		if _, ok := supported[scope]; !ok {
			return "", fmt.Errorf("requested scope %q is not supported", scope)
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return strings.Join(result, " "), nil
}

func (s *Server) signAuthorizationTicket(request *authorizationRequest) (string, error) {
	now := s.now()
	claims := authorizationTicketClaims{
		Type:          "authorization-request",
		ClientID:      request.ClientID,
		ClientName:    request.Client.ClientName,
		RedirectURI:   request.RedirectURI,
		CodeChallenge: request.CodeChallenge,
		Resource:      request.Resource,
		Scope:         request.Scope,
		State:         request.State,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.issuer + "/oauth/login"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

func (s *Server) verifyAuthorizationTicket(ticket string) (*authorizationTicketClaims, error) {
	claims := &authorizationTicketClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(s.issuer+"/oauth/login"),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(s.now),
	)
	parsed, err := parser.ParseWithClaims(ticket, claims, func(*jwt.Token) (any, error) { return s.secret, nil })
	if err != nil || !parsed.Valid || claims.Type != "authorization-request" {
		return nil, errors.New("invalid authorization ticket")
	}
	if claims.ClientID == "" || claims.ClientName == "" || claims.RedirectURI == "" || claims.CodeChallenge == "" || claims.Resource != s.resource {
		return nil, errors.New("authorization ticket is incomplete")
	}
	return claims, nil
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request, identity Identity) {
	if strings.TrimSpace(identity.Subject) == "" {
		writeOAuthError(w, http.StatusUnauthorized, "access_denied", "authenticated identity is required")
		return
	}
	if r.Method == http.MethodGet {
		ticket := r.URL.Query().Get("ticket")
		claims, client, err := s.resolveTicket(r, ticket)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		s.renderConsent(w, ticket, claims, client)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !isFormContentType(r.Header.Get("Content-Type")) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "application/x-www-form-urlencoded required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid login request")
		return
	}
	ticket := r.PostForm.Get("ticket")
	claims, _, err := s.resolveTicket(r, ticket)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if r.PostForm.Get("decision") != "approve" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", appendRedirectParams(claims.RedirectURI, map[string]string{
			"error": "access_denied", "state": claims.State, "iss": s.issuer,
		}))
		w.WriteHeader(http.StatusFound)
		return
	}
	code, err := s.state.IssueAuthorizationCode(AuthorizationCodeRecord{
		ClientID:      claims.ClientID,
		RedirectURI:   claims.RedirectURI,
		CodeChallenge: claims.CodeChallenge,
		Resource:      claims.Resource,
		Scope:         claims.Scope,
		Subject:       identity.Subject,
		Email:         identity.Email,
	}, s.authorizationCodeTTL)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue authorization code")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", appendRedirectParams(claims.RedirectURI, map[string]string{
		"code": code, "state": claims.State, "iss": s.issuer,
	}))
	w.WriteHeader(http.StatusFound)
}

func (s *Server) resolveTicket(r *http.Request, ticket string) (*authorizationTicketClaims, ClientMetadata, error) {
	if strings.TrimSpace(ticket) == "" {
		return nil, ClientMetadata{}, errors.New("authorization ticket is required")
	}
	claims, err := s.verifyAuthorizationTicket(ticket)
	if err != nil {
		return nil, ClientMetadata{}, err
	}
	client, err := s.clients.Resolve(r.Context(), claims.ClientID)
	if err != nil {
		return nil, ClientMetadata{}, errors.New("OAuth client registration is no longer valid")
	}
	if !containsString(client.RedirectURIs, claims.RedirectURI) {
		return nil, ClientMetadata{}, errors.New("client registration changed during authorization")
	}
	return claims, client, nil
}

func (s *Server) renderConsent(w http.ResponseWriter, ticket string, claims *authorizationTicketClaims, client ClientMetadata) {
	// remaining methods (handleToken, handleRevoke, helpers) are unchanged from the
	// previous implementation and live in the same package; they are not duplicated
	// here to keep this patch focused on route registration control.
	_ = client
	data := consentData{
		Ticket:       ticket,
		ClientName:   claims.ClientName,
		Resource:     claims.Resource,
		Scope:        claims.Scope,
		RedirectHost: redirectHost(claims.RedirectURI),
		Loopback:     isLoopbackRedirect(claims.RedirectURI),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = consentPage.Execute(w, data)
}
