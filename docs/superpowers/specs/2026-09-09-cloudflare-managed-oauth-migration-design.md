# Cloudflare Access Managed OAuth Migration for superfast-mcp

Date: 2026-09-09
Status: Approved design, pending implementation plan

## Context

`superfast-mcp` currently terminates OAuth itself in the Go process and exposes that native OAuth surface through a custom Cloudflare Worker that forwards to a public plaintext HTTP origin. ChatGPT can complete parts of the OAuth flow, but connector finalization/tool discovery remains unstable with HTTP 424 responses. The current Cloudflare edge also demonstrably returns Cloudflare error 1010 to some non-browser HTTP client fingerprints.

The known-good production reference is `https://mcp.tnaprovider.com.au/mcp`. Its stable ChatGPT path does not use the origin's native OAuth implementation as the primary authorization server. Instead, Cloudflare Access Managed OAuth protects `/mcp`, returns the RFC 9728 challenge and protected-resource metadata, performs DCR/PKCE/authorization/token/refresh/revocation, and forwards a signed `Cf-Access-Jwt-Assertion` to the origin. The origin validates that assertion before serving MCP.

## Goal

Migrate `https://superfast.heidiai.com.au/mcp` to the same trust-boundary pattern as the stable reference:

1. Cloudflare Access Managed OAuth owns public `/mcp` authentication.
2. The Go origin validates Cloudflare Access assertions.
3. ChatGPT discovers and completes OAuth through Cloudflare's managed authorization server.
4. The existing static bearer remains only as a controlled origin/break-glass path.
5. The existing native OAuth implementation remains temporarily available only for rollback during migration and is no longer the public ChatGPT-advertised path.
6. Public qualification verifies the exact OAuth/MCP edge contract before the migration is considered complete.

## Non-goals

- Rewriting the MCP tool implementation.
- Changing the current eight-tool surface as part of this migration.
- Adding a UI/widget.
- Broadly weakening Cloudflare WAF/Bot protections.
- Treating the native `/oauth/*` reference implementation as the primary production OAuth path.

## Target request flow

```text
ChatGPT
  -> POST https://superfast.heidiai.com.au/mcp
  <- 401 + WWW-Authenticate resource_metadata=<Cloudflare Access metadata>

ChatGPT
  -> Cloudflare protected-resource metadata
  -> Cloudflare Access authorization-server metadata
  -> Cloudflare DCR
  -> Cloudflare authorization + PKCE
  -> Cloudflare token/refresh/revocation

ChatGPT
  -> Authorization: Bearer <Cloudflare-managed access token> -> /mcp
Cloudflare Access
  -> validates managed OAuth credential
  -> injects signed Cf-Access-Jwt-Assertion
  -> forwards request to origin
Go origin
  -> validates JWT signature, issuer, audience, owner identity and JWT time claims
  -> applies resource/custom-scope restrictions only when those claims are intentionally used
  -> serves MCP server/discover, tools/list and tools/call
```

## Cloudflare configuration

Create or convert an Access application for `superfast.heidiai.com.au/mcp` with Managed OAuth enabled.

Required behavior:

- Destination covers `/mcp` and `/mcp/*` only.
- Managed OAuth dynamic client registration is enabled.
- ChatGPT callback `https://chatgpt.com/connector_platform_oauth_redirect` is explicitly allowed.
- Public-client token endpoint auth method `none` is supported.
- PKCE S256 is required/supported.
- Authorization-code and refresh-token grants are enabled.
- Scope `mcp` is allowed.
- Access policy restricts the resource to the intended owner identity.
- WAF/Bot policy allows standards-valid OAuth/MCP traffic for this hostname and avoids the current client-fingerprint false positive without globally disabling protection.

Expected unauthenticated `/mcp` challenge shape is Cloudflare-owned, analogous to the reference:

```text
HTTP 401
WWW-Authenticate: Bearer ... resource_metadata="https://superfast.heidiai.com.au/.well-known/cloudflare-access-protected-resource/mcp"
```

The corresponding protected-resource metadata must point to the configured Cloudflare Access authorization server rather than the Go server's native OAuth issuer.

## Go origin authentication

Add a Cloudflare Access authentication mode alongside the existing static/native mechanisms.

Configuration fields:

- Access issuer/team domain
- Access audience/application AUD
- MCP resource URL
- allowed owner email or equivalent subject policy
- optional required scopes for deployments that intentionally add a trusted custom `scope` claim; unset for standard Cloudflare Access JWTs
- Access JWKS URL/team certs endpoint

For requests reaching `/mcp`, the origin should authenticate in this order:

1. Valid `Cf-Access-Jwt-Assertion` and configured Cloudflare Access mode.
2. Valid static bearer token for explicitly trusted origin/break-glass use.
3. Native OAuth access token only while rollback compatibility is retained.
4. Reject otherwise.

Cloudflare assertion validation must verify:

- RS256 signature against Access JWKS
- exact issuer
- exact audience
- `resource` when present equals `https://superfast.heidiai.com.au/mcp`
- allowed owner identity
- configured custom scope restrictions only when the deployment intentionally supplies a trusted `scope` claim
- non-empty subject
- normal JWT time validation

Authentication failures must not log the assertion or bearer token.

## Public/native OAuth routing during migration

The public ChatGPT path is Cloudflare Managed OAuth. Native Go OAuth endpoints may remain reachable temporarily for rollback qualification, but `/mcp` must advertise the Cloudflare Access protected-resource URL, not the Go native metadata URL.

After a successful observation period, native OAuth can be deprecated separately. That removal is not part of this migration unless explicitly approved later.

## Edge/origin transport

The current Worker uses `http://34.40.224.186.sslip.io` and leaves the origin publicly reachable. This is not acceptable as the long-term trust path for OAuth tokens or assertions.

Preferred target: Cloudflare Tunnel or another private/authenticated Cloudflare-to-origin path.

Migration sequencing may temporarily preserve the current origin path only if required to avoid combining two large changes in one cutover, but the Managed OAuth qualification must not be used as evidence that plaintext/public origin transport is secure. Closing the public origin is a required follow-up before the deployment is considered hardened.

## MCP behavior

The Go MCP server remains stateless Streamable HTTP. No tool-schema change is required for the OAuth migration.

Qualification must verify:

- unauthenticated modern `server/discover` receives the Cloudflare-owned 401 challenge
- authenticated `server/discover` returns HTTP 200 and advertises tools
- authenticated `tools/list` returns exactly the current eight tools
- protocol `2026-07-28` works
- legacy supported versions continue working unless a separate compatibility decision is made

## Public-edge qualification canary

Port the reference production qualification pattern into `superfast-mcp` as a script/testable command.

The canary must verify without exposing credentials:

1. `/health` is 200 and reports the expected version/release.
2. unauthenticated `/mcp` modern discovery is 401.
3. `WWW-Authenticate` contains an absolute RFC 9728 `resource_metadata` URL.
4. that URL is the Cloudflare Access protected-resource path.
5. protected-resource metadata resource equals the exact MCP URL.
6. it advertises at least one authorization server.
7. authorization-server metadata issuer matches the advertised server.
8. authorization/token/registration endpoints are absolute HTTPS URLs.
9. PKCE S256, authorization-code and refresh-token support are advertised.
10. DCR for ChatGPT returns 201, preserves the callback URI, and does not contradict the requested application type when that optional response field is present.
11. an authorization-stage probe for the registered ChatGPT callback is accepted and does not return an OAuth error.
12. token endpoint invalid-grant probes return structured OAuth JSON rather than a WAF/interstitial page.
13. non-browser client probes do not receive Cloudflare 1010 on OAuth discovery/DCR.
14. an authenticated MCP probe returns all eight tools.

The canary must record only bounded metadata such as status, content type, route, timing and Cloudflare Ray ID. It must never print OAuth codes, PKCE verifiers, bearer/access/refresh tokens, cookies or Access JWT assertions.

## Testing strategy

Test-driven implementation order:

1. Unit tests for Cloudflare Access JWT validation using an in-memory/generated RSA key and JWKS.
2. HTTP handler tests proving a standard valid Access assertion reaches `/mcp`, invalid issuer/audience/resource/identity is rejected, and any explicitly configured custom scope restriction is enforced.
3. Regression test proving static bearer still works for trusted origin use.
4. Regression test proving native OAuth continues working while rollback compatibility remains enabled.
5. Public-edge qualification script tests using fixture HTTP servers where practical.
6. Full Go test/race/vet/staticcheck/govulncheck/build gate.
7. Exact-commit VM test/build gate.
8. Cloudflare public-edge qualification against production.
9. ChatGPT fresh app connection/Scan Tools qualification.

## Deployment sequence

1. Record current `origin/main`, deployed binary hash and Cloudflare config.
2. Implement and verify Go Access assertion support without changing public edge mode.
3. Deploy the backward-compatible Go release.
4. Configure Cloudflare Access Managed OAuth for `/mcp` and exact ChatGPT redirect URI.
5. Verify Cloudflare DCR and authorization-stage callback acceptance before cutover.
6. Enable Managed OAuth protection on `/mcp`.
7. Run the public-edge canary and require the Cloudflare-managed challenge.
8. Run authenticated MCP qualification and require all eight tools.
9. Recreate/refresh the ChatGPT app and require Scan Tools to populate the eight-tool snapshot.
10. Observe logs/edge telemetry for errors.
11. Preserve rollback to prior Worker/native-OAuth mode until qualification is complete.

## Rollback

If Managed OAuth qualification fails:

- Restore the previous Cloudflare route/protection mode.
- Keep the backward-compatible Go release if it does not alter the previous native/static behavior.
- Re-run native OAuth and MCP contract checks.
- Do not patch the deployed immutable binary in place.
- Preserve Cloudflare Ray IDs and sanitized route/status telemetry for diagnosis.

## Security follow-ups required after OAuth cutover

These are separate from the OAuth compatibility migration but remain mandatory hardening items discovered in the audit:

- replace `--roots /home/heidi` with narrow project roots
- move all MCP/OAuth secrets outside MCP-readable roots
- run the service under a dedicated least-privilege identity
- sandbox or containerize `run_command`
- close direct public origin access and replace plaintext Worker->origin HTTP with a private/authenticated path
- add correct MCP tool annotations for read-only/destructive/open-world behavior
- add production request telemetry that never logs credentials

## Acceptance criteria

The migration is complete only when all of the following are true:

- public `/mcp` challenge is Cloudflare Access Managed OAuth, not native Go OAuth
- default non-browser HTTP probes no longer hit Cloudflare 1010 on the qualified OAuth paths
- DCR accepts ChatGPT's exact callback
- authorization and token flows support PKCE and refresh tokens
- Go validates Access assertions before serving MCP
- authenticated `server/discover` and `tools/list` return the expected eight tools
- the full source and VM release gates pass
- ChatGPT completes OAuth and Scan Tools without HTTP 424
- the ChatGPT app exposes the eight tools in a fresh/updated action snapshot
