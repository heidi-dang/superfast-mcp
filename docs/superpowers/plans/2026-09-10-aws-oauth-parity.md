# AWS OAuth Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reproduce the stable AWS `mcp.tnaprovider.com.au` dual-layer OAuth architecture in Superfast: Cloudflare Access Managed OAuth remains the public `/mcp` authorization layer while the Go origin gains the AWS-parity native `/oauth/*` subsystem with durable state, DCR/CIMD, PKCE, refresh rotation/revocation, and Cloudflare-authenticated consent.

**Architecture:** Keep Superfast's eight MCP tools unchanged. Replace the current password-based/in-memory native OAuth implementation with focused Go components for configuration, signed client metadata, SSRF-safe CIMD resolution, SQLite-backed grant state, OAuth protocol endpoints, and resource-bound access-token verification. The public Cloudflare Managed OAuth edge remains authoritative for unauthenticated `/mcp`; native OAuth is independently qualified at the origin and exposed on the same hostname as the AWS fallback contract.

**Tech Stack:** Go 1.25.12+ (qualification with Go 1.26.7), `github.com/golang-jwt/jwt/v5`, `modernc.org/sqlite` via `database/sql`, `github.com/modelcontextprotocol/go-sdk v1.7.0`, Cloudflare Access Managed OAuth, systemd, Caddy/Worker edge.

**Spec:** `docs/superpowers/specs/2026-09-10-aws-oauth-parity-design.md`

## Global Constraints

- Preserve the exact eight-tool MCP surface: `ping`, `read_file`, `write_file`, `list_dir`, `run_command`, `git_status`, `git_diff`, `git_log`.
- Public unauthenticated `/mcp` must continue to advertise Cloudflare Access Managed OAuth through `/.well-known/cloudflare-access-protected-resource/mcp`.
- Origin-native OAuth uses `/.well-known/oauth-protected-resource[/mcp]` and `/oauth/*`; it must not replace the public Managed OAuth challenge.
- Native OAuth production mode requires a dedicated secret of at least 32 characters, a durable state DB outside MCP-readable roots, and Cloudflare Access verification for `/oauth/login`.
- Native access tokens are HS256, resource-bound, approximately 15 minutes; authorization codes approximately 5 minutes; refresh grants approximately 14 days.
- Refresh tokens rotate. Reuse of a used token revokes the entire refresh family. Explicit revocation revokes the family.
- DCR supports public clients only (`token_endpoint_auth_method=none`), PKCE S256, `authorization_code` + `refresh_token`, response type `code`, and `web`/`native` application types.
- CIMD supports HTTPS client IDs only and must block private, loopback, link-local, CGNAT, documentation, multicast, reserved, and unique-local destinations before connecting.
- Never log OAuth codes, state, PKCE verifier/challenge, access/refresh tokens, Cloudflare assertions, cookies, authorization headers, owner credentials, or request bodies.
- Existing static bearer remains break-glass. Existing Cloudflare Access assertion authentication remains supported.
- Existing unstaged telemetry edits in the source checkout are not part of this branch unless intentionally reimplemented after review.
- Every production mutation must have a recorded rollback artifact and an immediate health/auth qualification step.

---

## File Structure

### New files

- `internal/oauth/client_metadata.go` — DCR signed-client IDs, redirect validation, CIMD fetch/cache, DNS/IP SSRF validation, PKCE helper.
- `internal/oauth/client_metadata_test.go` — DCR/CIMD/redirect/SSRF parity tests.
- `internal/oauth/state.go` — SQLite schema, hashed one-time authorization codes, refresh-family rotation/reuse/revocation.
- `internal/oauth/state_test.go` — one-time code, expiry, restart persistence, refresh rotation/reuse/revoke tests.
- `internal/oauth/token.go` — native HS256 access-token claims, minting, verification.
- `internal/oauth/token_test.go` — issuer/audience/use/time/subject/client validation tests.
- `internal/oauth/server_test.go` — metadata, DCR, authorize-ticket, login consent, token, refresh, revoke, RFC 9207 tests.
- `internal/edgecheck/native.go` — origin-native OAuth parity checker reusable by tests/CLI.
- `internal/edgecheck/native_test.go` — fixture contract tests for native metadata/DCR/PKCE/refresh/revoke.

### Modified files

- `go.mod`, `go.sum` — add pure-Go SQLite driver selected by `go get modernc.org/sqlite@latest` and pin the resolved version.
- `internal/config/config.go` — explicit native OAuth configuration and version bump.
- `internal/config/config_test.go` — complete/partial native configuration and version tests.
- `internal/oauth/server.go` — replace current owner-password/in-memory implementation with AWS-parity route handlers and authorization tickets.
- `internal/mcp/server.go` — build native OAuth independently from static bearer; wrap `/oauth/login` with Cloudflare identity verification; register `/oauth/*` routes.
- `internal/mcp/http_auth.go` — consume the new native access-token verifier without changing auth precedence.
- `internal/mcp/http_auth_test.go`, `internal/mcp/oauth_test.go`, `internal/mcp/server_test.go` — parity integration tests and exact eight-tool verification.
- `cmd/superfast-edgecheck/main.go` — optional native-origin qualification mode without exposing credentials.
- `deploy/env.example`, `README.md` — document dual-layer Managed OAuth + native fallback configuration.
- `docs/superpowers/specs/2026-09-10-aws-oauth-parity-design.md` — update status/version only if implementation reveals a factual correction.

### Production-only files/config

- `/var/lib/superfast-mcp/oauth/state.db` — durable OAuth state, directory mode 0750 or stricter, not beneath `/home/heidi`.
- `/etc/systemd/system/superfast-mcp.service.d/native-oauth.conf` — environment-file/drop-in reference and `ReadWritePaths=/var/lib/superfast-mcp/oauth` if service hardening requires it.
- Existing `/home/heidi/.config/superfast-mcp/*` protected secrets remain untouched until migration config is atomically prepared.

---

### Task 1: Add explicit native OAuth configuration and SQLite dependency

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `deploy/env.example`
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Produces:

```go
type NativeOAuthConfig struct {
    Issuer  string
    Resource string
    Scopes []string
    Secret string
    StateDB string
}

type Config struct {
    // existing fields unchanged
    NativeOAuth *NativeOAuthConfig
}
```

- Environment variables:

```text
SUPERFAST_NATIVE_OAUTH_ISSUER
SUPERFAST_NATIVE_OAUTH_RESOURCE
SUPERFAST_NATIVE_OAUTH_SCOPES
SUPERFAST_NATIVE_OAUTH_SECRET
SUPERFAST_NATIVE_OAUTH_DB
```

- Native OAuth is disabled when all five are unset. If any are set, require `SUPERFAST_PUBLIC_URL`, secret length >= 32, a non-empty DB path, and a complete Cloudflare Access configuration so `/oauth/login` can fail closed on owner identity.
- Default issuer to `SUPERFAST_PUBLIC_URL`, resource to `<public-url>/mcp`, scopes to `mcp` when native OAuth is enabled.
- Version target: `0.3.0` because the native OAuth route/config contract changes incompatibly from `/authorize` to `/oauth/authorize`.

- [ ] **Step 1: Write failing native-config tests**

Add tests equivalent to:

```go
func TestParseArgsReadsNativeOAuthConfiguration(t *testing.T) {
    cfg, err := ParseArgs([]string{"--http-only"}, envMap(map[string]string{
        "SUPERFAST_AUTH_TOKEN":              "break-glass",
        "SUPERFAST_PUBLIC_URL":              "https://superfast.example.com",
        "SUPERFAST_CF_ACCESS_ISSUER":         "https://team.cloudflareaccess.com",
        "SUPERFAST_CF_ACCESS_AUDIENCE":       "app-aud",
        "SUPERFAST_CF_ACCESS_ALLOWED_EMAIL":  "owner@example.com",
        "SUPERFAST_NATIVE_OAUTH_SECRET":       strings.Repeat("s", 32),
        "SUPERFAST_NATIVE_OAUTH_DB":           "/var/lib/superfast-mcp/oauth/state.db",
    }))
    if err != nil { t.Fatal(err) }
    if cfg.NativeOAuth == nil { t.Fatal("missing native OAuth config") }
    if cfg.NativeOAuth.Issuer != "https://superfast.example.com" { t.Fatalf("issuer=%q", cfg.NativeOAuth.Issuer) }
    if cfg.NativeOAuth.Resource != "https://superfast.example.com/mcp" { t.Fatalf("resource=%q", cfg.NativeOAuth.Resource) }
    if !slices.Equal(cfg.NativeOAuth.Scopes, []string{"mcp"}) { t.Fatalf("scopes=%v", cfg.NativeOAuth.Scopes) }
}

func TestParseArgsRejectsNativeOAuthWithoutCloudflareLoginIdentity(t *testing.T) {
    _, err := ParseArgs([]string{"--http-only"}, envMap(map[string]string{
        "SUPERFAST_AUTH_TOKEN":         "break-glass",
        "SUPERFAST_PUBLIC_URL":         "https://superfast.example.com",
        "SUPERFAST_NATIVE_OAUTH_SECRET": strings.Repeat("s", 32),
        "SUPERFAST_NATIVE_OAUTH_DB":     "/var/lib/superfast-mcp/oauth/state.db",
    }))
    if err == nil || !strings.Contains(err.Error(), "Cloudflare Access") { t.Fatalf("err=%v", err) }
}

func TestCurrentVersion(t *testing.T) {
    cfg, err := ParseArgs([]string{"--allow-unauthenticated-http"}, envMap(nil))
    if err != nil { t.Fatal(err) }
    if cfg.Version != "0.3.0" { t.Fatalf("version=%q", cfg.Version) }
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
GO=/home/shacker/Desktop/superfast-mcp/.cptr/toolchains/go1.26.7/bin/go
$GO test ./internal/config -run 'NativeOAuth|CurrentVersion' -count=1
```

Expected: compile/test failure because `NativeOAuthConfig` does not exist and version remains `0.2.1`.

- [ ] **Step 3: Implement minimal config parsing and fail-closed validation**

Parse the five variables above. Normalize issuer/public URL by removing one trailing slash. Validate issuer/resource as absolute HTTPS URLs. Parse scopes on commas or spaces, deduplicate while preserving order, and reject empty scope names. Do not derive the native secret from the static bearer.

- [ ] **Step 4: Add and pin SQLite dependency**

Run:

```bash
GO=/home/shacker/Desktop/superfast-mcp/.cptr/toolchains/go1.26.7/bin/go
$GO get modernc.org/sqlite@latest
$GO mod tidy
```

The resolved version must be committed in `go.mod`/`go.sum`; do not leave an unpinned local replacement.

- [ ] **Step 5: Update `deploy/env.example` with placeholders only**

Add:

```text
# Native OAuth fallback parity with the stable AWS origin.
# Requires complete Cloudflare Access config for /oauth/login identity verification.
# SUPERFAST_NATIVE_OAUTH_ISSUER=https://superfast.example.com
# SUPERFAST_NATIVE_OAUTH_RESOURCE=https://superfast.example.com/mcp
# SUPERFAST_NATIVE_OAUTH_SCOPES=mcp
# SUPERFAST_NATIVE_OAUTH_SECRET=replace-with-32-plus-character-secret
# SUPERFAST_NATIVE_OAUTH_DB=/var/lib/superfast-mcp/oauth/state.db
```

Mark `SUPERFAST_OAUTH_OWNER_PASSWORD` deprecated/unused by the AWS-parity native flow; do not delete it from production environment during this task.

- [ ] **Step 6: Run config tests GREEN**

```bash
$GO test ./internal/config -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit Task 1**

```bash
git add go.mod go.sum internal/config/config.go internal/config/config_test.go deploy/env.example
git commit -m "feat: configure durable native oauth"
```

---

### Task 2: Implement durable SQLite OAuth grant state

**Files:**
- Create: `internal/oauth/state.go`
- Create: `internal/oauth/state_test.go`

**Interfaces:**

```go
type AuthorizationCodeRecord struct {
    ClientID      string `json:"client_id"`
    RedirectURI   string `json:"redirect_uri"`
    CodeChallenge string `json:"code_challenge"`
    Resource      string `json:"resource"`
    Scope         string `json:"scope"`
    Subject       string `json:"subject"`
    Email         string `json:"email,omitempty"`
}

type RefreshTokenRecord struct {
    ClientID string `json:"client_id"`
    Resource string `json:"resource"`
    Scope string `json:"scope"`
    Subject string `json:"subject"`
    Email string `json:"email,omitempty"`
    FamilyID string `json:"family_id"`
    ExpiresAt int64 `json:"expires_at"`
}

type StateStore struct { /* private database handle */ }
func OpenStateStore(path string) (*StateStore, error)
func (s *StateStore) Close() error
func (s *StateStore) IssueAuthorizationCode(record AuthorizationCodeRecord, ttl time.Duration) (string, error)
func (s *StateStore) ConsumeAuthorizationCode(code string) (*AuthorizationCodeRecord, error)
func (s *StateStore) IssueRefreshToken(record RefreshTokenRecord, expiresAt time.Time) (token string, stored RefreshTokenRecord, err error)
func (s *StateStore) RotateRefreshToken(token, clientID, resource string) (replacement string, record RefreshTokenRecord, err error)
func (s *StateStore) RevokeRefreshToken(token string) error
```

Use opaque prefixes `sfc_code_` and `sfc_refresh_`. Store only SHA-256 hex hashes, never plaintext values.

- [ ] **Step 1: Write failing state tests**

Cover:

```go
func TestAuthorizationCodesAreOneTimeAndPersistAcrossRestart(t *testing.T)
func TestAuthorizationCodeExpires(t *testing.T)
func TestRefreshTokenRotatesAndReuseRevokesFamily(t *testing.T)
func TestRefreshRevocationRevokesFamily(t *testing.T)
func TestStateDatabaseStoresHashesNotPlaintextTokens(t *testing.T)
```

The restart test must close and reopen the same file-backed DB before consuming the code. The family-reuse test must prove: first refresh succeeds and returns token B; reusing token A fails; token B then also fails because the family was revoked.

- [ ] **Step 2: Run tests and verify RED**

```bash
$GO test ./internal/oauth -run 'AuthorizationCode|RefreshToken|StateDatabase' -count=1
```

Expected: compile failure because `StateStore` does not exist.

- [ ] **Step 3: Implement SQLite schema and durability**

Use `database/sql` with blank import `_ "modernc.org/sqlite"`. On open:

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
  code_hash TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_authorization_codes_expiry ON oauth_authorization_codes(expires_at);
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expiry ON oauth_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_family ON oauth_refresh_tokens(family_id);
```

Set `db.SetMaxOpenConns(1)` so explicit `BEGIN IMMEDIATE` transactions are serialized predictably.

- [ ] **Step 4: Implement atomic consume/rotation/reuse-family revocation**

For code consume and refresh rotation, obtain one `*sql.Conn`, execute `BEGIN IMMEDIATE`, perform the read/update/insert, then explicit `COMMIT`; rollback on every error. A reused refresh (`used_at IS NOT NULL`) must update every row in the family with `revoked_at` before returning an invalid-token sentinel.

Expose sentinel errors:

```go
var ErrInvalidAuthorizationCode = errors.New("invalid authorization code")
var ErrInvalidRefreshToken = errors.New("invalid refresh token")
```

- [ ] **Step 5: Run state tests GREEN**

```bash
$GO test ./internal/oauth -run 'AuthorizationCode|RefreshToken|StateDatabase' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add internal/oauth/state.go internal/oauth/state_test.go
git commit -m "feat: persist oauth grant state"
```

---

### Task 3: Implement signed DCR clients, redirect validation, and SSRF-safe CIMD

**Files:**
- Create: `internal/oauth/client_metadata.go`
- Create: `internal/oauth/client_metadata_test.go`

**Interfaces:**

```go
type ClientMetadata struct {
    ClientID string
    ClientName string
    RedirectURIs []string
    TokenEndpointAuthMethod string
    ApplicationType string
}

type ClientRegistrationInput struct {
    ClientName string `json:"client_name"`
    RedirectURIs []string `json:"redirect_uris"`
    GrantTypes []string `json:"grant_types"`
    ResponseTypes []string `json:"response_types"`
    TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
    ApplicationType string `json:"application_type"`
}

type ClientResolver struct { /* secret, issuer, bounded cache, network hooks */ }
func NewClientResolver(issuer string, secret []byte) *ClientResolver
func (r *ClientResolver) IssueDynamicClient(input ClientRegistrationInput) (clientID string, metadata ClientMetadata, issuedAt int64, err error)
func (r *ClientResolver) Resolve(ctx context.Context, clientID string) (ClientMetadata, error)
func PKCES256(verifier string) string
```

DCR client IDs use `urn:superfast:oauth-client:<HS256-JWT>`. JWT claims contain `typ=dcr-client`, `client_name`, `redirect_uris`, `token_endpoint_auth_method=none`, `application_type`; issuer is the native issuer and audience is `<issuer>/oauth/register`.

- [ ] **Step 1: Write failing DCR/redirect tests**

Cover exact AWS behaviors:

```go
func TestIssueDynamicClientPreservesWebApplicationType(t *testing.T)
func TestIssueDynamicClientPreservesNativeLoopbackApplicationType(t *testing.T)
func TestIssueDynamicClientAcceptsClaudeGeminiAndGrokRedirectShapes(t *testing.T)
func TestIssueDynamicClientRejectsPrivateAuthMethodOrMissingAuthorizationCode(t *testing.T)
func TestValidateRedirectURIRejectsFragmentsCredentialsAndNonLoopbackHTTP(t *testing.T)
func TestDynamicClientIDRejectsTampering(t *testing.T)
```

Use the exact ChatGPT callback `https://chatgpt.com/connector_platform_oauth_redirect` in the web-client test.

- [ ] **Step 2: Run DCR tests RED**

```bash
$GO test ./internal/oauth -run 'DynamicClient|RedirectURI|ApplicationType' -count=1
```

Expected: compile failure because the resolver does not exist.

- [ ] **Step 3: Implement normalized public-client metadata and signed DCR IDs**

Rules: client name 1..160 chars; 1..20 redirects; HTTPS accepted; HTTP only for `localhost`, `127.0.0.0/8`, or `::1`; no fragment or URL credentials; `authorization_code` required when grant list supplied; `code` required when response list supplied; auth method must be `none`; application type `web|native`, default `web`; deduplicate redirects preserving order.

- [ ] **Step 4: Write failing CIMD SSRF tests**

Cover:

```go
func TestCIMDRejectsNonHTTPSDefaultPortMissingPathCredentialsAndFragment(t *testing.T)
func TestCIMDRejectsLocalAndPrivateResolvedAddresses(t *testing.T)
func TestCIMDRequiresExactClientIDAndJSONBody(t *testing.T)
func TestCIMDUsesBoundedCache(t *testing.T)
```

The private-address table must include IPv4 loopback/RFC1918/CGNAT/link-local/documentation/multicast/reserved and IPv6 loopback/ULA/link-local/documentation/multicast.

- [ ] **Step 5: Implement CIMD fetcher with injectable lookup/dial hooks**

Production behavior:

- `https:` only, default port 443 only, non-root path, no credentials/fragment.
- Resolve all addresses with `net.DefaultResolver.LookupIPAddr`; reject if any resolved IP is not globally public under the explicit blocked-range table.
- Pin the connection to one validated address using a cloned `http.Transport.DialContext` while preserving `TLSClientConfig.ServerName=url.Hostname()`.
- 3-second request timeout; `Accept: application/json`; no redirects; 32 KiB body cap; JSON content type required.
- Require metadata `client_id` exactly equals the requested URL; normalize the same client metadata fields as DCR.
- Cache at most 256 documents, default 5 minutes, cap parsed `Cache-Control: max-age` at 60 minutes.

Test hooks must be package-private fields/functions; production callers use safe defaults.

- [ ] **Step 6: Run client-metadata tests GREEN**

```bash
$GO test ./internal/oauth -run 'DynamicClient|RedirectURI|CIMD|ApplicationType' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```bash
git add internal/oauth/client_metadata.go internal/oauth/client_metadata_test.go
git commit -m "feat: resolve oauth client metadata"
```

---

### Task 4: Implement native access-token JWTs

**Files:**
- Create: `internal/oauth/token.go`
- Create: `internal/oauth/token_test.go`

**Interfaces:**

```go
type TokenIdentity struct {
    Subject string
    Email string
    ClientID string
    Scope string
}

type TokenIssuer struct { /* issuer/resource/key/clock */ }
func NewTokenIssuer(issuer, resource string, secret []byte) (*TokenIssuer, error)
func (i *TokenIssuer) MintAccessToken(identity TokenIdentity, ttl time.Duration) (string, error)
func (i *TokenIssuer) VerifyAccessToken(token string) (TokenIdentity, error)
```

Claims:

```json
{
  "token_use":"access",
  "client_id":"...",
  "scope":"mcp",
  "email":"owner@example.com",
  "iss":"https://superfast.example.com",
  "aud":["https://superfast.example.com/mcp"],
  "sub":"owner-subject",
  "iat":..., "nbf":..., "exp":...
}
```

- [ ] **Step 1: Write failing token tests**

```go
func TestAccessTokenRoundTrip(t *testing.T)
func TestAccessTokenRejectsWrongIssuerAudienceAndSignature(t *testing.T)
func TestAccessTokenRejectsExpiredAndFutureNBF(t *testing.T)
func TestAccessTokenRejectsWrongUseMissingSubjectAndMissingClient(t *testing.T)
```

- [ ] **Step 2: Run tests RED**

```bash
$GO test ./internal/oauth -run 'AccessToken' -count=1
```

Expected: compile failure because `TokenIssuer` does not exist.

- [ ] **Step 3: Implement HS256 token mint/verify**

Use `jwt/v5`; parser valid methods only `HS256`, exact issuer/audience, expiration required, 30-second leeway. Require `token_use=access`, non-empty `sub`, non-empty `client_id`. Do not accept refresh-token formats in this verifier.

- [ ] **Step 4: Run token tests GREEN**

```bash
$GO test ./internal/oauth -run 'AccessToken' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit Task 4**

```bash
git add internal/oauth/token.go internal/oauth/token_test.go
git commit -m "feat: issue native oauth access tokens"
```

---

### Task 5: Replace the native OAuth protocol server with AWS-parity endpoints

**Files:**
- Modify: `internal/oauth/server.go`
- Create: `internal/oauth/server_test.go`
- Remove obsolete password-form assertions from: `internal/mcp/oauth_test.go` later in Task 6, not in this task.

**Interfaces:**

```go
type Identity struct {
    Subject string
    Email string
}

type ServerConfig struct {
    Issuer string
    Resource string
    Scopes []string
    Secret string
    StateDB string
    AccessTokenTTL time.Duration // zero => 15m
    GrantTTL time.Duration       // zero => 14d
    AuthorizationCodeTTL time.Duration // zero => 5m
}

func New(cfg ServerConfig) (*Server, error)
func (s *Server) Close() error
func (s *Server) RegisterProtocolRoutes(mux *http.ServeMux)
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request, identity Identity)
func (s *Server) ResourceMetadataURL() string
func (s *Server) VerifyAccessToken(token string) bool
```

`RegisterProtocolRoutes` registers both native RFC 9728 metadata paths, `/.well-known/oauth-authorization-server`, `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`; `/oauth/login` is registered by the MCP HTTP layer so it can verify Cloudflare identity first.

- [ ] **Step 1: Write failing metadata/DCR route tests**

Require authorization metadata exactly includes:

```json
{
  "issuer":"https://superfast.example.com",
  "authorization_endpoint":"https://superfast.example.com/oauth/authorize",
  "token_endpoint":"https://superfast.example.com/oauth/token",
  "registration_endpoint":"https://superfast.example.com/oauth/register",
  "revocation_endpoint":"https://superfast.example.com/oauth/revoke",
  "response_types_supported":["code"],
  "response_modes_supported":["query"],
  "grant_types_supported":["authorization_code","refresh_token"],
  "token_endpoint_auth_methods_supported":["none"],
  "code_challenge_methods_supported":["S256"],
  "client_id_metadata_document_supported":true,
  "protected_resources":["https://superfast.example.com/mcp"],
  "scopes_supported":["mcp"]
}
```

DCR route must return 201 and preserve ChatGPT callback/application type.

- [ ] **Step 2: Run metadata/DCR tests RED**

```bash
$GO test ./internal/oauth -run 'Metadata|Register|DCR' -count=1
```

Expected: failures because current endpoints are `/register`, `/authorize`, `/token` and metadata lacks revocation/CIMD fields.

- [ ] **Step 3: Implement metadata and `/oauth/register` using ClientResolver**

Use 64 KiB body limit, JSON object only, structured `invalid_client_metadata` on validation failure, `Cache-Control: no-store` and `Pragma: no-cache` for OAuth JSON.

- [ ] **Step 4: Write failing authorize/login ticket tests**

Cover:

```go
func TestAuthorizeRedirectsToSignedLoginTicket(t *testing.T)
func TestAuthorizeRejectsWrongResourceRedirectPKCEAndScope(t *testing.T)
func TestLoginApproveIssuesCodeStateAndRFC9207Issuer(t *testing.T)
func TestLoginDenyReturnsAccessDenied(t *testing.T)
func TestLoginRevalidatesClientRegistration(t *testing.T)
```

Authorize GET must 302 to `/oauth/login?ticket=...`. Login GET with an already supplied trusted identity must return consent HTML containing client name/resource/scopes but no owner password input. Login POST `decision=approve` returns callback with `code`, original `state`, and `iss=<native issuer>`.

- [ ] **Step 5: Implement signed authorization tickets and consent**

Ticket is HS256 JWT, max 10 minutes, issuer native issuer, audience `<issuer>/oauth/login`, `typ=authorization-request`; claims include client ID/name, redirect, PKCE challenge, resource, scope, state. Re-resolve client on login GET/POST and require registered redirect still matches.

Consent CSP must be restrictive: `default-src 'none'`, inline style only, `form-action 'self' <redirect-origin>`, `base-uri 'none'`, `frame-ancestors 'none'`; no script required.

- [ ] **Step 6: Write failing token/refresh/revoke route tests**

Cover the complete flow: DCR -> authorize -> approve -> code exchange -> native access token verifies -> refresh returns a different refresh token -> reuse of old token fails -> replacement then fails because family revoked. Add explicit revoke test and a test proving token handler logs nothing containing submitted credentials.

- [ ] **Step 7: Implement `/oauth/token` and `/oauth/revoke`**

Token endpoint requires `application/x-www-form-urlencoded`, max 64 KiB. Authorization-code verifier must match `^[A-Za-z0-9._~-]{43,128}$`; code binding includes client, redirect, resource, PKCE. Every successful code exchange issues access + refresh. Refresh uses StateStore rotation. Revoke always returns 200 `{}` and revokes refresh family if recognized.

OAuth access-token TTL default 15 minutes; grant TTL default 14 days; code TTL default 5 minutes.

- [ ] **Step 8: Run complete OAuth package tests GREEN**

```bash
$GO test ./internal/oauth -count=1
```

Expected: PASS.

- [ ] **Step 9: Commit Task 5**

```bash
git add internal/oauth/server.go internal/oauth/server_test.go
git commit -m "feat: match aws native oauth protocol"
```

---

### Task 6: Integrate Cloudflare-authenticated consent and native bearer into MCP HTTP

**Files:**
- Modify: `internal/mcp/server.go`
- Modify: `internal/mcp/http_auth.go`
- Modify: `internal/mcp/http_auth_test.go`
- Modify: `internal/mcp/oauth_test.go`
- Modify: `internal/mcp/server_test.go`

**Interfaces:**
- `NewHTTPHandler` builds `access.Verifier` once from `cfg.CloudflareAccess`.
- If `cfg.NativeOAuth != nil`, construct `oauth.New(oauth.ServerConfig{...})`, call `RegisterProtocolRoutes`, and register `/oauth/login` wrapper.
- `/oauth/login` wrapper reads only `Cf-Access-Jwt-Assertion`, calls the Access verifier, returns structured 401 JSON when absent/invalid, and otherwise calls `nativeOAuth.HandleLogin(..., oauth.Identity{Subject: id.Subject, Email: id.Email})`.
- MCP auth order remains Access assertion -> static bearer -> native access token -> reject.

- [ ] **Step 1: Write failing `/oauth/login` identity tests**

```go
func TestNativeOAuthLoginFailsClosedWithoutCloudflareAssertion(t *testing.T)
func TestNativeOAuthLoginAcceptsVerifiedCloudflareIdentity(t *testing.T)
```

Use a fake Access verifier in a focused helper or inject verifier creation through a package-private constructor helper. The first test must return 401 without rendering consent. The second must render the no-password consent page for a valid ticket.

- [ ] **Step 2: Run login integration tests RED**

```bash
$GO test ./internal/mcp -run 'NativeOAuthLogin' -count=1
```

Expected: failures because current login is the password form at `/authorize` and no `/oauth/login` wrapper exists.

- [ ] **Step 3: Implement native server construction and login wrapper**

Native OAuth is independent of `AuthToken`: static bearer may be empty while native OAuth is configured. Change the HTTP wrapper to an explicit closable concrete type:

```go
type HTTPHandler struct {
    handler http.Handler
    nativeOAuth *oauthserver.Server
}
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.handler.ServeHTTP(w, r) }
func (h *HTTPHandler) Close() error {
    if h.nativeOAuth != nil { return h.nativeOAuth.Close() }
    return nil
}
func NewHTTPHandler(cfg *config.Config) (*HTTPHandler, error)
```

`RunHTTP` must `defer handler.Close()` immediately after construction. Existing tests continue calling `ServeHTTP`; tests that create native OAuth handlers add `t.Cleanup(func(){ _ = handler.Close() })`. This makes SQLite lifetime explicit and prevents DB-handle leakage.

- [ ] **Step 4: Replace old owner-password OAuth tests with AWS-parity flow**

`internal/mcp/oauth_test.go` must perform:

```text
POST /oauth/register
GET /oauth/authorize
GET/POST /oauth/login with verified fake Access identity
POST /oauth/token authorization_code
POST /mcp tools/list with native access token
POST /oauth/token refresh_token
POST /oauth/revoke
```

Require successful MCP response and exactly eight tool names.

- [ ] **Step 5: Add negative native bearer tests**

Prove wrong issuer/audience/expiry/nbf/use/subject/client fail through MCP auth while static bearer and valid Access assertion still pass.

- [ ] **Step 6: Run MCP tests GREEN**

```bash
$GO test ./internal/mcp -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit Task 6**

```bash
git add internal/mcp/server.go internal/mcp/http_auth.go internal/mcp/http_auth_test.go internal/mcp/oauth_test.go internal/mcp/server_test.go
git commit -m "feat: integrate aws parity oauth with mcp"
```

---

### Task 7: Add native-origin parity qualification and documentation

**Files:**
- Create: `internal/edgecheck/native.go`
- Create: `internal/edgecheck/native_test.go`
- Modify: `cmd/superfast-edgecheck/main.go`
- Modify: `README.md`
- Modify: `deploy/env.example` if names changed during implementation.

**Interfaces:**

```go
type NativeOptions struct {
    Origin string
    Resource string
    ChatGPTRedirect string
    Timeout time.Duration
}

type NativeResult struct {
    Issuer string
    DCRApplicationType string
    RevocationAdvertised bool
    CIMDSupported bool
}

func CheckNative(ctx context.Context, client *http.Client, opts NativeOptions) (NativeResult, error)
```

CLI env:

```text
SUPERFAST_EDGE_NATIVE_ORIGIN     optional; when set, run native-origin parity checks in addition to public Managed OAuth checks
```

No token/credential is accepted by CLI args.

- [ ] **Step 1: Write failing native edgecheck fixture test**

Fixture must emulate AWS native metadata at `/oauth/*`, DCR 201, authorization PKCE 302 to login, structured invalid refresh response, revoke 200. Require `response_modes_supported=query`, revocation endpoint, CIMD flag, exact protected resource, S256, public token auth, auth-code + refresh grants, and ChatGPT DCR callback/application type.

- [ ] **Step 2: Run native edgecheck test RED**

```bash
$GO test ./internal/edgecheck -run Native -count=1
```

Expected: compile failure because `CheckNative` does not exist.

- [ ] **Step 3: Implement native checker and CLI integration**

Keep public `Check` unchanged for Cloudflare Managed OAuth. `CheckNative` independently verifies origin/native contract; it must not infer that public `/mcp` should advertise native OAuth.

- [ ] **Step 4: Update README dual-layer architecture**

Document:

```text
Public ChatGPT path: Cloudflare Access Managed OAuth protects /mcp.
Native fallback path: origin exposes /.well-known/oauth-* and /oauth/* with Cloudflare-authenticated consent.
```

Include state DB path requirement and a warning not to place DB/secrets under MCP-readable roots.

- [ ] **Step 5: Run focused tests GREEN**

```bash
$GO test ./internal/edgecheck ./cmd/superfast-edgecheck -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit Task 7**

```bash
git add internal/edgecheck/native.go internal/edgecheck/native_test.go cmd/superfast-edgecheck/main.go README.md deploy/env.example
git commit -m "test: qualify native oauth parity"
```

---

### Task 8: Full source release gate and exact candidate

**Files:** none unless a gate exposes a defect.

- [ ] **Step 1: Verify tracked state and formatting**

```bash
git status --short
git diff --check
$GO fmt ./...
```

If `go fmt ./...` changes files, inspect the diff and commit formatting with the owning task rather than a drive-by broad refactor.

- [ ] **Step 2: Run full Go gate**

```bash
$GO test -count=1 ./...
$GO test -race -count=1 ./...
$GO vet ./...
PATH="/home/shacker/Desktop/superfast-mcp/.cptr/toolchains/go1.26.7/bin:$PATH" staticcheck ./...
PATH="/home/shacker/Desktop/superfast-mcp/.cptr/toolchains/go1.26.7/bin:$PATH" govulncheck ./...
$GO build -trimpath -o /tmp/superfast-mcp-0.3.0 ./cmd/superfast-mcp
$GO build -trimpath -o /tmp/superfast-edgecheck-0.3.0 ./cmd/superfast-edgecheck
sha256sum /tmp/superfast-mcp-0.3.0 /tmp/superfast-edgecheck-0.3.0
```

Expected: every command exits 0 and `govulncheck` reports no affecting vulnerabilities.

- [ ] **Step 3: Run SDK MCP contract probe**

Use the existing ignored `.cptr/oauth-sdk-check.go` from the main checkout or copy it unchanged into an ignored worktree-local temp path. Require:

```text
SDK_OAUTH_OK tools=8
```

Do not weaken the probe if it fails; investigate protocol drift.

- [ ] **Step 4: Record exact candidate**

```bash
git rev-parse HEAD
git status --short
```

Tracked state must be clean before deployment.

---

### Task 9: Push and deploy exact 0.3.0 origin with protected OAuth state

**Production surfaces:** GitHub `main`, GCP/Heidi VM `alie`, systemd, `/var/lib/superfast-mcp/oauth`.

- [ ] **Step 1: Integrate branch into `main` without losing pre-existing telemetry edits**

Before integration, inspect the original checkout's unstaged files. Preserve them exactly. Fast-forward/merge only committed parity changes. If the unstaged telemetry changes overlap committed parity files, stop and reconcile explicitly; never reset or discard them.

- [ ] **Step 2: Push verified candidate**

```bash
git fetch origin
git rev-list --left-right --count origin/main...HEAD
git push origin main
```

No force push. Require expected divergence only.

- [ ] **Step 3: Snapshot current production rollback state**

On `alie`, record without printing secrets:

```text
current binary SHA256
current systemd unit/drop-ins
current release HEAD
current health/version
current public /mcp challenge mode
```

Copy the current binary to a timestamped rollback path. Copy service/drop-in files to a root-readable rollback directory or preserve their exact non-secret structure; do not print environment secret values.

- [ ] **Step 4: Provision OAuth state directory outside MCP roots**

Create `/var/lib/superfast-mcp/oauth` owned by the service account, mode 0750 or stricter. State DB must be `/var/lib/superfast-mcp/oauth/state.db`. Add `ReadWritePaths=/var/lib/superfast-mcp/oauth` if the current unit hardening needs it.

- [ ] **Step 5: Prepare native OAuth secret/config through protected runtime only**

Configure the five `SUPERFAST_NATIVE_OAUTH_*` values. Reuse no static bearer as the signing secret. Do not print the secret, Access AUD, owner email, assertions, tokens, cookies, OAuth code, state, or PKCE material.

- [ ] **Step 6: Build exact pushed SHA on VM and install atomically**

Create `/home/heidi/services/superfast-mcp-releases/<full-sha>`, run:

```bash
go test -count=1 ./...
go vet ./...
go build -trimpath -o superfast-mcp ./cmd/superfast-mcp
go build -trimpath -o superfast-edgecheck ./cmd/superfast-edgecheck
sha256sum superfast-mcp superfast-edgecheck
```

Install the exact VM-built `superfast-mcp`, restart systemd, wait for readiness.

- [ ] **Step 7: Qualify loopback native OAuth without real owner credentials**

Require:

```text
/health -> version 0.3.0
/.well-known/oauth-authorization-server -> native /oauth/* metadata
/.well-known/oauth-protected-resource/mcp -> native issuer/resource
synthetic invalid Cf-Access-Jwt-Assertion on /oauth/login -> 401
static bearer MCP path -> live production probe only through an existing host-protected secret-injection mechanism; if CPTR blocks safe injection, record `SAFETY-SKIPPED` and rely on the green in-process/static-bearer regression test without reading or printing the production token
```

Use package tests for full approve/token flow if a valid Access assertion cannot be supplied safely at loopback.

---

### Task 10: Normalize Cloudflare configuration against AWS and run public parity

**Cloudflare surfaces:** Access application(s), Managed OAuth config, Browser Integrity configuration rule. No origin source changes unless evidence exposes a defect.

- [ ] **Step 1: Read-only diff target vs reference**

Compare live public behavior first:

```text
/mcp status + resource_metadata challenge
Cloudflare protected-resource metadata keys/authorization server
Cloudflare authorization-server metadata keys
DCR 201 response keys
PKCE authorization-stage redirect class
invalid refresh structured JSON class
```

Then inspect dashboard fields only if behavior differs.

- [ ] **Step 2: Preserve current target edge snapshot**

Record Access app ID/name/destination/policy name, Managed OAuth enabled state, exact ChatGPT callback allowlist, localhost/loopback allowances, Browser Integrity exception rule, Worker deployment/custom-domain IDs. No tokens/cookies.

- [ ] **Step 3: Change only fields proven different from stable AWS**

Do not globally disable WAF/Bot. Do not wildcard redirect URI. Do not remove the hostname-scoped Browser Integrity exception that is required for default non-browser OAuth clients. Preserve public Managed OAuth on `/mcp`.

- [ ] **Step 4: Run public Managed OAuth edge gate**

From exact release:

```bash
SUPERFAST_EDGE_MCP_URL=https://superfast.heidiai.com.au/mcp \
  ./superfast-edgecheck
```

Require `auth=cloudflare-managed`, no 1010/interstitial, valid DCR/PKCE/token probes.

- [ ] **Step 5: Run native-origin parity gate**

Use the safe origin/loopback path or public native metadata endpoints as appropriate:

```bash
SUPERFAST_EDGE_MCP_URL=https://superfast.heidiai.com.au/mcp \
SUPERFAST_EDGE_NATIVE_ORIGIN=https://superfast.heidiai.com.au \
  ./superfast-edgecheck
```

Require native metadata/DCR/PKCE/revocation fields to normalize to the AWS reference.

- [ ] **Step 6: Run independent default Python `urllib` comparison**

No custom User-Agent. Require target and reference both avoid 1010 and return the same status/content classes for public challenge, Cloudflare protected metadata, Cloudflare DCR, and native metadata/DCR.

---

### Task 11: Fresh ChatGPT connector acceptance

**Surface:** connected Heidi Chrome/ChatGPT Plugins developer UI. Use a new app record; do not reuse stale `superfast` records.

- [ ] **Step 1: Confirm connected browser and take scoped lease**

Use CPTR paired Chrome. If the device is offline, stop this task as `NEEDS_CONTEXT` without changing production server/edge configuration.

- [ ] **Step 2: Create a brand-new custom app**

Server URL exactly:

```text
https://superfast.heidiai.com.au/mcp
```

Authentication: OAuth / dynamically discovered. Confirm the discovered auth/token/registration endpoints belong to `heidiluong.cloudflareaccess.com` for the public Managed OAuth path.

- [ ] **Step 3: Complete Cloudflare Managed OAuth with a real user gesture if Chrome requires transient activation**

Do not bypass popup/user-activation security with runtime patches. If automation cannot open the OAuth popup, transfer lease to human for the single sign-in gesture, then retake only after callback.

- [ ] **Step 4: Capture sanitized callback/action evidence**

During OAuth completion and Scan Tools, record only request path class, status, timestamp, and `cf-ray` where available. Never record token/code/state/cookie/assertion values.

- [ ] **Step 5: Require exact eight actions and no 424**

Expected:

```text
ping
read_file
write_file
list_dir
run_command
git_status
git_diff
git_log
```

Any HTTP 424 or zero-action snapshot is a failure. Use production telemetry to locate whether the failure is Cloudflare callback, origin Access validation, MCP discover, or tools/list before changing code.

- [ ] **Step 6: Reconnect/refresh-cycle acceptance**

After first success, reconnect/refresh once and ensure the app remains connected and still exposes all eight tools. This proves refresh-token/session behavior is stable.

---

### Task 12: Final verification and rollback retention

- [ ] **Step 1: Run verification-before-completion gate**

Require:

```text
origin/main contains exact deployed SHA
systemd active
health version 0.3.0
installed binary hash equals exact VM build
public /mcp auth mode = cloudflare-managed
public edge gate passes
native origin parity gate passes
OAuth state DB exists outside /home/heidi and is service-writable only
ChatGPT fresh app tools = 8
HTTP 424 absent
reconnect/refresh cycle succeeds
```

- [ ] **Step 2: Keep rollback state**

Do not delete pre-0.3.0 binary, prior release directory, previous service config snapshot, or Cloudflare edge snapshot until the connector has remained stable through the acceptance cycle. Do not delete stale ChatGPT app records as part of this migration; cleanup is separate.

- [ ] **Step 3: Update progress/design status**

Mark the design implemented only after every acceptance criterion above passes. Document any intentionally skipped authenticated CLI check with its safety reason; do not convert a skipped check into a claimed pass.
