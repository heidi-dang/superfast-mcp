# Cloudflare Managed OAuth Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the public `superfast.heidiai.com.au/mcp` trust boundary to Cloudflare Access Managed OAuth while preserving static/native rollback paths and proving ChatGPT can discover all eight MCP tools without HTTP 424.

**Architecture:** Cloudflare Access becomes the public OAuth authorization layer for `/mcp`; the Go origin accepts only requests authenticated by a validated `Cf-Access-Jwt-Assertion`, the existing break-glass bearer, or the existing native OAuth token during rollback compatibility. A new Access verifier validates RS256 JWTs against cached Cloudflare JWKS, and a production edge qualification command verifies the same RFC 9728/DCR/PKCE contract used by the stable `mcp.tnaprovider.com.au` deployment.

**Tech Stack:** Go 1.25.12+, `github.com/modelcontextprotocol/go-sdk v1.7.0`, `github.com/golang-jwt/jwt/v5`, Cloudflare Access Managed OAuth, Cloudflare Worker/Caddy, systemd.

**Spec:** `docs/superpowers/specs/2026-09-09-cloudflare-managed-oauth-migration-design.md`

## Global Constraints

- Public `/mcp` authentication is owned by Cloudflare Access Managed OAuth after cutover.
- Preserve the current eight-tool MCP surface unchanged during this migration.
- Preserve static bearer authentication as an origin/break-glass path.
- Preserve native Go OAuth temporarily for rollback, but do not advertise it to ChatGPT after Access cutover.
- Never log `Authorization`, `Cf-Access-Jwt-Assertion`, OAuth codes, PKCE verifiers, access/refresh tokens, cookies, or owner credentials.
- Require exact issuer, audience, owner identity, `mcp` scope, non-empty subject, JWT time validity, and matching `resource` when that claim is present.
- Do not globally disable Cloudflare WAF/Bot protections; use the narrowest hostname/path policy required.
- Production acceptance requires ChatGPT OAuth + Scan Tools to complete without HTTP 424 and expose exactly eight tools.
- Keep the existing public-origin/plaintext-HTTP architecture as an explicitly documented temporary risk; private/authenticated origin transport is a separate hardening follow-up.

---

## File Structure

### New files

- `internal/access/verifier.go` — Cloudflare Access JWT/JWKS verification, cache, identity result, and verifier interface.
- `internal/access/verifier_test.go` — generated-RSA/JWKS tests for signature, issuer, audience, identity, scope, resource, expiry, and key rotation.
- `internal/mcp/http_auth.go` — composable HTTP MCP authentication middleware and challenge behavior.
- `internal/mcp/http_auth_test.go` — middleware tests for Access assertion, static bearer, native OAuth fallback, and rejection.
- `internal/edgecheck/check.go` — reusable public-edge qualification logic.
- `internal/edgecheck/check_test.go` — fixture HTTP-server tests for Cloudflare-managed metadata/DCR/token/authorization probes and WAF/interstitial rejection.
- `cmd/superfast-edgecheck/main.go` — operator-facing production qualification command.

### Modified files

- `go.mod`, `go.sum` — add `github.com/golang-jwt/jwt/v5` as a direct dependency.
- `internal/config/config.go` — Access configuration model, environment parsing, validation, and version bump.
- `internal/config/config_test.go` — complete/partial Access configuration tests.
- `internal/mcp/server.go` — construct the Access verifier, register native rollback routes, and route `/mcp` through the new auth middleware.
- `internal/mcp/server_test.go` — handler construction/challenge/health regression coverage.
- `internal/mcp/oauth_test.go` — prove native OAuth remains functional during migration.
- `deploy/env.example` — document Access environment variables without secrets.
- `README.md` — document Cloudflare-managed mode vs native rollback mode and the edge-check command.

### Deployment/config surfaces (not committed secrets)

- `/etc/systemd/system/superfast-mcp.service.d/cloudflare-access.conf` or the existing owner-readable environment file — Access issuer, AUD, allowed email, JWKS URL.
- Cloudflare Access application for `superfast.heidiai.com.au/mcp` — Managed OAuth, ChatGPT callback allowlist, owner policy.
- Existing Worker remains the HTTP reverse proxy unless the Cloudflare Access configuration requires a route adjustment; no Worker behavior change is accepted without a before/after edge contract test.

---

### Task 1: Add Cloudflare Access configuration with fail-closed validation

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `deploy/env.example`

**Interfaces:**
- Produces: `config.CloudflareAccessConfig` with fields `Issuer`, `Audience`, `AllowedEmail`, `JWKSURL`, `Resource`, `RequiredScopes`.
- Produces: `Config.CloudflareAccess *CloudflareAccessConfig`.
- Later tasks consume `Config.CloudflareAccess` to construct the Access verifier.

- [ ] **Step 1: Write failing config tests**

Add tests equivalent to:

```go
func TestParseArgsReadsCloudflareAccessConfiguration(t *testing.T) {
    cfg, err := ParseArgs([]string{"--http-only"}, envMap(map[string]string{
        "SUPERFAST_AUTH_TOKEN":              "secret",
        "SUPERFAST_PUBLIC_URL":              "https://superfast.example.com",
        "SUPERFAST_CF_ACCESS_ISSUER":         "https://team.cloudflareaccess.com/",
        "SUPERFAST_CF_ACCESS_AUDIENCE":       "app-aud",
        "SUPERFAST_CF_ACCESS_ALLOWED_EMAIL":  "owner@example.com",
        "SUPERFAST_CF_ACCESS_JWKS_URL":       "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        "SUPERFAST_CF_ACCESS_REQUIRED_SCOPES": "mcp",
    }))
    if err != nil { t.Fatal(err) }
    if cfg.CloudflareAccess == nil { t.Fatal("missing Cloudflare Access config") }
    if cfg.CloudflareAccess.Issuer != "https://team.cloudflareaccess.com" { t.Fatalf("issuer=%q", cfg.CloudflareAccess.Issuer) }
    if cfg.CloudflareAccess.Resource != "https://superfast.example.com/mcp" { t.Fatalf("resource=%q", cfg.CloudflareAccess.Resource) }
    if !slices.Equal(cfg.CloudflareAccess.RequiredScopes, []string{"mcp"}) { t.Fatalf("scopes=%v", cfg.CloudflareAccess.RequiredScopes) }
}

func TestParseArgsRejectsPartialCloudflareAccessConfiguration(t *testing.T) {
    _, err := ParseArgs([]string{"--http-only"}, envMap(map[string]string{
        "SUPERFAST_AUTH_TOKEN":      "secret",
        "SUPERFAST_PUBLIC_URL":      "https://superfast.example.com",
        "SUPERFAST_CF_ACCESS_ISSUER": "https://team.cloudflareaccess.com",
    }))
    if err == nil { t.Fatal("expected partial Access configuration to fail") }
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/config -run 'CloudflareAccess' -count=1
```

Expected: compile/test failure because `CloudflareAccessConfig` and `Config.CloudflareAccess` do not exist.

- [ ] **Step 3: Implement minimal config model and validation**

Add:

```go
type CloudflareAccessConfig struct {
    Issuer         string
    Audience       string
    AllowedEmail   string
    JWKSURL        string
    Resource       string
    RequiredScopes []string
}
```

Parse these variables:

```text
SUPERFAST_CF_ACCESS_ISSUER
SUPERFAST_CF_ACCESS_AUDIENCE
SUPERFAST_CF_ACCESS_ALLOWED_EMAIL
SUPERFAST_CF_ACCESS_JWKS_URL
SUPERFAST_CF_ACCESS_REQUIRED_SCOPES
```

Rules:

- If none are set, `Config.CloudflareAccess == nil`.
- If any are set, require issuer, audience, allowed email, and a non-empty `SUPERFAST_PUBLIC_URL`.
- Normalize issuer by trimming one trailing `/`.
- Default JWKS URL to `<issuer>/cdn-cgi/access/certs` when omitted.
- Resource is always `<public-url>/mcp`.
- Default required scopes to `[]string{"mcp"}`.
- Reject an issuer/JWKS URL that is not absolute HTTPS.
- Reject empty scope entries.

- [ ] **Step 4: Run config tests GREEN**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/config -count=1
```

Expected: PASS.

- [ ] **Step 5: Update `deploy/env.example`**

Document the variables with non-secret placeholders only:

```text
# Cloudflare Access Managed OAuth origin validation (optional until cutover)
# SUPERFAST_CF_ACCESS_ISSUER=https://your-team.cloudflareaccess.com
# SUPERFAST_CF_ACCESS_AUDIENCE=replace-with-access-application-aud
# SUPERFAST_CF_ACCESS_ALLOWED_EMAIL=owner@example.com
# SUPERFAST_CF_ACCESS_JWKS_URL=https://your-team.cloudflareaccess.com/cdn-cgi/access/certs
# SUPERFAST_CF_ACCESS_REQUIRED_SCOPES=mcp
```

- [ ] **Step 6: Commit Task 1**

```bash
git add internal/config/config.go internal/config/config_test.go deploy/env.example
git commit -m "feat: configure Cloudflare Access auth"
```

---

### Task 2: Implement RS256 Cloudflare Access JWT verification with JWKS caching

**Files:**
- Create: `internal/access/verifier.go`
- Create: `internal/access/verifier_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Produces:

```go
type Identity struct {
    Subject string
    Email   string
    Scope   string
}

type Verifier interface {
    Verify(ctx context.Context, assertion string) (Identity, error)
}

func NewVerifier(cfg config.CloudflareAccessConfig, client *http.Client) (*JWTVerifier, error)
```

- `JWTVerifier.Verify` consumes the `Cf-Access-Jwt-Assertion` value only; it never receives the full request headers.
- Task 3 injects this `Verifier` into the MCP HTTP auth middleware.

- [ ] **Step 1: Add direct JWT dependency**

Run:

```bash
.cptr/toolchains/go1.26.7/bin/go get github.com/golang-jwt/jwt/v5
```

Pin the version selected by Go modules and keep it direct in `go.mod`.

- [ ] **Step 2: Write failing verifier tests**

Generate a test RSA key and JWKS fixture. Cover:

```go
func TestVerifierAcceptsValidAccessAssertion(t *testing.T)
func TestVerifierRejectsWrongIssuer(t *testing.T)
func TestVerifierRejectsWrongAudience(t *testing.T)
func TestVerifierRejectsWrongEmail(t *testing.T)
func TestVerifierRejectsMissingScope(t *testing.T)
func TestVerifierRejectsResourceMismatch(t *testing.T)
func TestVerifierAllowsMissingResourceClaim(t *testing.T)
func TestVerifierRejectsExpiredAssertion(t *testing.T)
func TestVerifierRejectsNonRS256(t *testing.T)
func TestVerifierRefreshesJWKSOnUnknownKID(t *testing.T)
```

The valid JWT payload should contain:

```json
{
  "iss": "https://team.cloudflareaccess.com",
  "aud": ["app-aud"],
  "sub": "subject-1",
  "email": "owner@example.com",
  "scope": "mcp",
  "resource": "https://superfast.example.com/mcp",
  "iat": 1788948000,
  "nbf": 1788948000,
  "exp": 1788948900
}
```

- [ ] **Step 3: Run tests and verify RED**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/access -count=1
```

Expected: package/functions missing.

- [ ] **Step 4: Implement JWKS loader and verifier**

Use `github.com/golang-jwt/jwt/v5` for JWT parsing/claim validation and standard-library RSA/JWK conversion.

Key requirements:

```go
type accessClaims struct {
    Email    string `json:"email"`
    Scope    string `json:"scope"`
    Resource string `json:"resource,omitempty"`
    jwt.RegisteredClaims
}
```

Construct the parser with RS256 only and issuer/audience enforcement:

```go
jwt.NewParser(
    jwt.WithValidMethods([]string{"RS256"}),
    jwt.WithIssuer(cfg.Issuer),
    jwt.WithAudience(cfg.Audience),
    jwt.WithExpirationRequired(),
    jwt.WithLeeway(30*time.Second),
)
```

JWKS behavior:

- Fetch with `Accept: application/json` and a bounded 5-second HTTP client timeout.
- Cap response body at 256 KiB.
- Accept RSA JWKs with non-empty `kid`, `n`, and `e`.
- Cache keys for at most 5 minutes.
- Refresh immediately once on unknown `kid` to support Cloudflare key rotation.
- Do not log the JWT or JWKS response body.

Post-signature claim checks:

```go
if !strings.EqualFold(claims.Email, cfg.AllowedEmail) { reject }
if claims.Subject == "" { reject }
if claims.Resource != "" && claims.Resource != cfg.Resource { reject }
for _, required := range cfg.RequiredScopes {
    if !scopeSet[required] { reject }
}
```

- [ ] **Step 5: Run verifier tests GREEN**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/access -count=1
```

Expected: PASS.

- [ ] **Step 6: Run dependency security check**

```bash
PATH="$PWD/.cptr/toolchains/go1.26.7/bin:$PATH" govulncheck ./internal/access/...
```

Expected: no vulnerabilities affecting the package.

- [ ] **Step 7: Commit Task 2**

```bash
git add go.mod go.sum internal/access/verifier.go internal/access/verifier_test.go
git commit -m "feat: verify Cloudflare Access assertions"
```

---

### Task 3: Route MCP authentication through Access → static bearer → native OAuth

**Files:**
- Create: `internal/mcp/http_auth.go`
- Create: `internal/mcp/http_auth_test.go`
- Modify: `internal/mcp/server.go`
- Modify: `internal/mcp/server_test.go`
- Modify: `internal/mcp/oauth_test.go`

**Interfaces:**
- Consumes: `access.Verifier`, `config.CloudflareAccessConfig`, existing `oauth.Server`.
- Produces:

```go
type mcpAuthOptions struct {
    StaticToken string
    Access      access.Verifier
    NativeOAuth *oauth.Server
}

func authenticateMCP(options mcpAuthOptions, next http.Handler) http.Handler
```

Authentication order is fixed: valid Access assertion, static bearer, native OAuth bearer, reject.

- [ ] **Step 1: Write failing middleware tests**

Use a fake Access verifier so no network is involved:

```go
type fakeAccessVerifier struct {
    accepted string
}
func (f fakeAccessVerifier) Verify(_ context.Context, token string) (access.Identity, error) {
    if token != f.accepted { return access.Identity{}, errors.New("invalid") }
    return access.Identity{Subject: "owner", Email: "owner@example.com", Scope: "mcp"}, nil
}
```

Cover:

```go
func TestMCPAuthAcceptsCloudflareAccessAssertion(t *testing.T)
func TestMCPAuthRejectsInvalidCloudflareAssertion(t *testing.T)
func TestMCPAuthFallsBackToStaticBearer(t *testing.T)
func TestMCPAuthFallsBackToNativeOAuth(t *testing.T)
func TestMCPAuthRejectsMissingCredentials(t *testing.T)
func TestMCPAuthDoesNotTrustCfAssertionWithoutVerifier(t *testing.T)
```

- [ ] **Step 2: Run tests and verify RED**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/mcp -run 'MCPAuth' -count=1
```

Expected: compile failure because the new middleware does not exist.

- [ ] **Step 3: Implement the middleware**

Pseudo-logic must remain exact:

```go
if assertion := strings.TrimSpace(r.Header.Get("Cf-Access-Jwt-Assertion")); assertion != "" && options.Access != nil {
    if _, err := options.Access.Verify(r.Context(), assertion); err == nil {
        next.ServeHTTP(w, r)
        return
    }
}

scheme, bearer := parseBearer(r.Header.Get("Authorization"))
if scheme && constantTimeEqual(bearer, options.StaticToken) {
    next.ServeHTTP(w, r)
    return
}
if scheme && options.NativeOAuth != nil && options.NativeOAuth.VerifyAccessToken(bearer) {
    next.ServeHTTP(w, r)
    return
}
rejectMCP(w)
```

`rejectMCP` must remain structured and non-secret. Before Cloudflare cutover it may advertise the native metadata URL when native OAuth is configured; after cutover the public Access layer owns the externally observed 401.

- [ ] **Step 4: Integrate with `NewHTTPHandler`**

Construction rules:

- Create `access.NewVerifier` only when `cfg.CloudflareAccess != nil`.
- Continue constructing/registering native OAuth routes when `AuthToken` and `PublicURL` are present so rollback remains available.
- Replace `bearerAuthWithOAuth` wiring with `authenticateMCP`.
- Keep `/health`, `/`, body limits, and the MCP handler unchanged.

- [ ] **Step 5: Prove all three auth paths through the HTTP handler**

Add/adjust tests so:

- Access assertion reaches `tools/list`/MCP handler.
- Existing static bearer test still passes.
- Existing native OAuth authorization-code + refresh-token test still passes.
- Missing credentials still produce 401.

- [ ] **Step 6: Run MCP tests GREEN**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/mcp -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```bash
git add internal/mcp/http_auth.go internal/mcp/http_auth_test.go internal/mcp/server.go internal/mcp/server_test.go internal/mcp/oauth_test.go
git commit -m "feat: accept Cloudflare Access MCP identity"
```

---

### Task 4: Add a stable-reference public-edge qualification command

**Files:**
- Create: `internal/edgecheck/check.go`
- Create: `internal/edgecheck/check_test.go`
- Create: `cmd/superfast-edgecheck/main.go`

**Interfaces:**
- Produces:

```go
type Options struct {
    MCPURL           string
    ChatGPTRedirect  string
    ExpectedTools    []string
    AccessToken      string
    Timeout          time.Duration
}

type Result struct {
    AuthMode          string
    AuthorizationHost string
    ToolCount         int
}

func Check(ctx context.Context, client *http.Client, opts Options) (Result, error)
```

- `AccessToken` is optional for pre-cutover unauthenticated edge qualification; production acceptance runs a second authenticated check after a managed-OAuth token is available through the approved interactive flow.
- Command reads token only from `SUPERFAST_EDGE_ACCESS_TOKEN`; it never accepts/prints it as a positional CLI argument.

- [ ] **Step 1: Write fixture-based failing tests**

Create an `httptest.Server` that emulates the stable reference contract:

1. `/mcp` → `401` with `resource_metadata`.
2. protected-resource metadata → Access authorization server.
3. authorization metadata → DCR/token/authorize endpoints with PKCE and refresh grant.
4. DCR → `201`, preserving ChatGPT callback/application type.
5. authorization stage → `302` to an interactive identity URL without OAuth error.
6. invalid token probe → JSON OAuth error.

Tests:

```go
func TestCheckAcceptsCloudflareManagedOAuthContract(t *testing.T)
func TestCheckRejectsNativeResourceMetadataPath(t *testing.T)
func TestCheckRejectsHTMLTokenInterstitial(t *testing.T)
func TestCheckRejectsDCRCallbackMutation(t *testing.T)
func TestCheckRejectsMissingRefreshGrant(t *testing.T)
func TestCheckRejectsNonHTTPSMetadataInProductionMode(t *testing.T)
```

- [ ] **Step 2: Run tests and verify RED**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/edgecheck -count=1
```

Expected: package/functions missing.

- [ ] **Step 3: Implement unauthenticated edge qualification**

Required checks mirror the stable repo's `scripts/check-public-edge.mjs`:

- POST MCP `server/discover` with `MCP-Protocol-Version: 2026-07-28` and `Mcp-Method: server/discover`.
- Require 401.
- Parse `resource_metadata` from `WWW-Authenticate`.
- Require path `/.well-known/cloudflare-access-protected-resource/mcp`.
- Fetch and validate protected-resource metadata.
- Fetch authorization-server metadata from the advertised authorization server.
- Require HTTPS authorization/token/registration endpoints.
- Require S256, authorization_code, refresh_token, and public-client support.
- POST an intentionally invalid refresh-token request and require 400/401 structured JSON OAuth error.
- DCR with exact ChatGPT profile:

```json
{
  "client_name": "ChatGPT",
  "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "web"
}
```

- Require returned redirect URI and application type to match exactly.
- Probe authorization stage with PKCE S256 and require no OAuth error/interstitial.

- [ ] **Step 4: Add authenticated MCP qualification when `AccessToken` is present**

Use the token only in an `Authorization: Bearer` header. Execute `server/discover`, then `tools/list`, and require exactly:

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

Never include the token in errors. On HTTP error report only status, content type, bounded body classification (`json`, `html`, `text`), and `cf-ray` if present.

- [ ] **Step 5: Implement command wrapper**

`cmd/superfast-edgecheck/main.go` reads:

```text
SUPERFAST_EDGE_MCP_URL              default https://superfast.heidiai.com.au/mcp
SUPERFAST_EDGE_CHATGPT_REDIRECT     default https://chatgpt.com/connector_platform_oauth_redirect
SUPERFAST_EDGE_ACCESS_TOKEN         optional secret
SUPERFAST_EDGE_TIMEOUT              default 10s
```

On success print only:

```text
superfast edge verified: auth=cloudflare-managed auth_host=<host> tools=<n-or-unchecked>
```

- [ ] **Step 6: Run edgecheck tests GREEN**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/edgecheck ./cmd/superfast-edgecheck -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit Task 4**

```bash
git add internal/edgecheck cmd/superfast-edgecheck
git commit -m "test: add Cloudflare managed OAuth edge gate"
```

---

### Task 5: Document managed mode and bump the backward-compatible release

**Files:**
- Modify: `internal/config/config.go`
- Modify: `README.md`
- Modify: `deploy/env.example` if final names changed during Tasks 1–4.

**Interfaces:**
- Version target: `0.2.0` because the public authentication architecture changes while the MCP tool contract remains stable.

- [ ] **Step 1: Write a version regression test**

Add to `internal/config/config_test.go`:

```go
func TestCurrentVersion(t *testing.T) {
    cfg, err := ParseArgs([]string{"--allow-unauthenticated-http"}, envMap(nil))
    if err != nil { t.Fatal(err) }
    if cfg.Version != "0.2.0" { t.Fatalf("version=%q", cfg.Version) }
}
```

- [ ] **Step 2: Run version test RED**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/config -run TestCurrentVersion -count=1
```

Expected: FAIL with current `0.1.6`.

- [ ] **Step 3: Bump version and update README**

Document these two modes explicitly:

```text
Cloudflare managed mode (recommended production):
  Cloudflare Access owns public OAuth and /mcp challenge.
  Origin validates Cf-Access-Jwt-Assertion.

Native rollback mode:
  Go exposes its existing RFC 9728 + DCR + PKCE endpoints.
  Kept temporarily for rollback, not the recommended ChatGPT path.
```

Include the qualification command:

```bash
SUPERFAST_EDGE_MCP_URL=https://superfast.heidiai.com.au/mcp \
  go run ./cmd/superfast-edgecheck
```

Do not place Access AUDs, tokens, emails, or production secrets in the README.

- [ ] **Step 4: Run config/version tests GREEN**

```bash
.cptr/toolchains/go1.26.7/bin/go test ./internal/config -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit Task 5**

```bash
git add internal/config/config.go internal/config/config_test.go README.md deploy/env.example
git commit -m "docs: describe Cloudflare managed OAuth mode"
```

---

### Task 6: Run the complete source release gate before touching production

**Files:** none unless failures reveal a real defect.

**Interfaces:** Produces a release candidate Git SHA and binary hash. No Cloudflare or VM mutation occurs until this gate is green.

- [ ] **Step 1: Confirm only intended changes exist**

```bash
git status --short
git diff --check
```

Ignore only the pre-existing audit-generated `.fdx/` artifact; do not stage it.

- [ ] **Step 2: Run full Go verification**

```bash
export PATH="$PWD/.cptr/toolchains/go1.26.7/bin:$PATH"
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
staticcheck ./...
govulncheck ./...
go build -trimpath -o .cptr/bin/superfast-mcp ./cmd/superfast-mcp
go build -trimpath -o .cptr/bin/superfast-edgecheck ./cmd/superfast-edgecheck
sha256sum .cptr/bin/superfast-mcp .cptr/bin/superfast-edgecheck
```

Expected: all commands exit 0; `govulncheck` reports no affecting vulnerabilities.

- [ ] **Step 3: Run existing OAuth/MCP SDK compatibility probe**

Use `.cptr/oauth-sdk-check.go` or update that throwaway probe only if required to compile against the new middleware. Require:

```text
SDK_OAUTH_OK tools=8
```

The probe remains an uncommitted `.cptr` artifact.

- [ ] **Step 4: Record exact candidate SHA**

```bash
git rev-parse HEAD
git status --short
```

Do not deploy if tracked files are dirty.

---

### Task 7: Deploy the backward-compatible Go origin release before Access cutover

**Files:** production release directory/systemd environment; no source edits.

**Interfaces:** Consumes the exact source SHA from Task 6. Produces an origin that understands Cloudflare assertions while existing static/native auth still works.

- [ ] **Step 1: Push the verified Git commits**

```bash
git fetch origin
git status --short
git rev-list --left-right --count origin/main...HEAD
git push origin main
```

Require no unexpected upstream divergence.

- [ ] **Step 2: Create exact-SHA VM release checkout**

On `alie`, create/update:

```text
/home/heidi/services/superfast-mcp-releases/<full-sha>
```

Verify:

```bash
git rev-parse HEAD
```

must equal the pushed candidate SHA.

- [ ] **Step 3: Run VM gate on the exact checkout**

```bash
go test -count=1 ./...
go vet ./...
go build -trimpath -o superfast-mcp ./cmd/superfast-mcp
sha256sum superfast-mcp
```

- [ ] **Step 4: Install the binary atomically with rollback copy**

Preserve the currently deployed binary, install the exact-SHA build to `/usr/local/bin/superfast-mcp`, restart systemd, and wait for loopback readiness before declaring success.

- [ ] **Step 5: Verify pre-cutover compatibility**

Require:

```text
/health -> 0.2.0
native OAuth metadata -> 200
unauthenticated /mcp -> existing native 401 challenge
static bearer -> MCP tools/list works
```

Do not configure Access variables yet if the Access app does not exist.

---

### Task 8: Configure Cloudflare Access Managed OAuth for `superfast.heidiai.com.au/mcp`

**Files:** Cloudflare account configuration only; no repository source changes.

**Interfaces:** Produces the Access application/team issuer, application AUD, Managed OAuth DCR/PKCE policy, and exact owner access policy consumed by Task 9.

- [ ] **Step 1: Check current credential capabilities without printing credentials**

Determine whether the authenticated Cloudflare identity has permission equivalent to Access Apps and Policies Write. If only zone-read/Workers-write is available, stop this task at the permission boundary and perform the configuration through an authorized Cloudflare dashboard session/API credential; do not weaken the design.

- [ ] **Step 2: Snapshot current edge state**

Record non-secret values:

```text
Worker version/deployment ID
custom domain hostname
current /mcp status/challenge
current origin URL
current Access applications that match the hostname
```

- [ ] **Step 3: Create/convert the Access application**

Target destination:

```text
superfast.heidiai.com.au/mcp
superfast.heidiai.com.au/mcp/*
```

Enable Managed OAuth and preserve the existing Worker as origin handler.

- [ ] **Step 4: Configure Managed OAuth client policy**

Require:

```text
redirect URI: https://chatgpt.com/connector_platform_oauth_redirect
application type: web
public client / token endpoint auth none
authorization_code grant
refresh_token grant
PKCE S256
scope mcp
```

No wildcard redirect URI.

- [ ] **Step 5: Configure owner access policy**

Restrict Access to the intended owner identity. Record only the policy name/ID, never session cookies or identity tokens.

- [ ] **Step 6: Verify Cloudflare-owned unauthenticated contract before adding origin Access validation requirements**

Run:

```bash
go run ./cmd/superfast-edgecheck
```

Expected: Cloudflare-managed 401, protected-resource metadata, authorization metadata, DCR, PKCE authorization-stage probe, and structured token error all pass. Authenticated tool count may remain unchecked until a managed OAuth token exists.

If the command receives HTML, error 1010, or a native metadata path, do not continue.

---

### Task 9: Enable origin Access JWT validation with production values

**Files:** owner-readable systemd environment/drop-in only; no production secrets in Git.

**Interfaces:** Consumes Access issuer/AUD from Task 8. Produces a Go origin that accepts only valid Access assertions plus the preserved rollback mechanisms.

- [ ] **Step 1: Add non-secret/secret configuration through the protected service environment**

Configure:

```text
SUPERFAST_CF_ACCESS_ISSUER=https://<team>.cloudflareaccess.com
SUPERFAST_CF_ACCESS_AUDIENCE=<application-aud>
SUPERFAST_CF_ACCESS_ALLOWED_EMAIL=<owner-email>
SUPERFAST_CF_ACCESS_JWKS_URL=https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
SUPERFAST_CF_ACCESS_REQUIRED_SCOPES=mcp
```

Keep file mode `0600`, owned by `heidi`, and do not print the values in command output.

- [ ] **Step 2: Restart and verify local health/readiness**

Require systemd `active`, loopback listener present, and `/health` version `0.2.0`.

- [ ] **Step 3: Verify invalid Access assertion is rejected locally**

Send a synthetic invalid `Cf-Access-Jwt-Assertion` to loopback and require 401; never use a real assertion for this negative test.

- [ ] **Step 4: Verify break-glass/native rollback paths remain functional locally**

Static bearer and native OAuth compatibility tests must still pass against loopback/origin paths that legitimately support them.

---

### Task 10: Production qualification and ChatGPT acceptance

**Files:** no source changes unless qualification exposes a concrete defect; any defect returns to TDD in the relevant task.

**Interfaces:** Final acceptance gate from the approved design.

- [ ] **Step 1: Run public unauthenticated edge gate**

```bash
SUPERFAST_EDGE_MCP_URL=https://superfast.heidiai.com.au/mcp \
  /usr/local/bin/superfast-edgecheck
```

Require:

```text
auth=cloudflare-managed
Cloudflare protected-resource metadata path
Managed OAuth authorization server
DCR 201 for ChatGPT callback
PKCE authorization-stage acceptance
structured token error
no error 1010/interstitial
```

- [ ] **Step 2: Verify default non-browser fingerprint independently**

Repeat OAuth discovery and DCR using default Python `urllib` with no custom User-Agent. Require 200/201, matching the stable `mcp.tnaprovider.com.au` behavior.

- [ ] **Step 3: Complete one fresh ChatGPT OAuth connection**

Use a new connector/app state, not a prior failed OAuth callback. Complete Cloudflare's managed authorization flow through the owner identity.

- [ ] **Step 4: Capture only sanitized origin/edge evidence during Scan Tools**

Record UTC timestamp, path/method classification, status, and `cf-ray` where available. Do not capture bearer credentials, Access JWTs, cookies, codes, or PKCE values.

- [ ] **Step 5: Require ChatGPT Scan Tools to expose exactly eight tools**

Expected snapshot:

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

No HTTP 424 is accepted.

- [ ] **Step 6: Run authenticated edge check if a short-lived managed OAuth token can be supplied safely**

```bash
SUPERFAST_EDGE_ACCESS_TOKEN='<supplied-through-protected-runtime-only>' \
  /usr/local/bin/superfast-edgecheck
```

Require `tools=8`. Do not put the token in shell history; use the host's protected secret-input mechanism or environment injection. If the platform cannot safely supply the token, the successful ChatGPT Scan Tools result is the authenticated end-to-end evidence and this CLI sub-check remains skipped with that reason recorded.

- [ ] **Step 7: Final production verification**

Require:

```text
systemd active
/health version 0.2.0
production binary hash matches exact deployed build
origin/main contains deployed SHA
public auth mode cloudflare-managed
ChatGPT tool snapshot count = 8
HTTP 424 absent in the fresh flow
```

- [ ] **Step 8: Preserve rollback state**

Keep the previous binary/release directory and prior Cloudflare configuration snapshot until the new connection remains stable through at least one refresh/reconnect cycle.

---

## Post-migration hardening backlog (explicitly outside this plan)

Do not mix these with the OAuth migration unless a concrete dependency blocks the cutover:

1. Replace `--roots /home/heidi` with narrow project roots.
2. Move MCP/OAuth secrets outside every MCP-readable root.
3. Run the service under a dedicated least-privilege identity.
4. Sandbox/containerize `run_command`.
5. Replace public plaintext Worker → origin HTTP with Cloudflare Tunnel/private authenticated origin.
6. Add accurate MCP read-only/destructive/open-world annotations.
7. Add durable sanitized request telemetry.

These remain mandatory security work after the compatibility migration.
