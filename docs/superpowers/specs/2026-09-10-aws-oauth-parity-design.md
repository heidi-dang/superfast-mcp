# Superfast MCP AWS OAuth Parity Design

Date: 2026-09-10
Status: Approved architecture; implementation pending written-spec review
Reference production: `https://mcp.tnaprovider.com.au/mcp`
Target production: `https://superfast.heidiai.com.au/mcp`

## Objective

Replace Superfast MCP's current mixed OAuth implementation with the authentication architecture and native OAuth behavior proven in the stable AWS deployment serving `mcp.tnaprovider.com.au/mcp`, while preserving Superfast's existing eight MCP tools and rollback paths.

The reference implementation is the immutable AWS release currently used by `cptr-mcp.service`. The migration should reproduce its observable OAuth contract and trust boundaries rather than merely copying endpoint names.

## Ground-truth AWS architecture

The AWS reference intentionally uses two authentication layers with different public roles:

1. **Cloudflare Access Managed OAuth is the live public ChatGPT authorization layer for `/mcp`.** The current production 401 challenge from `https://mcp.tnaprovider.com.au/mcp` points to `/.well-known/cloudflare-access-protected-resource/mcp`, whose `authorization_servers` contains `https://heidiluong.cloudflareaccess.com`. This edge behavior is authoritative for the ChatGPT path.
2. **The origin also hosts a complete native OAuth 2.1 server as an alternate/fallback authorization path.** Its issuer is the MCP public origin and it exposes native RFC 9728/RFC 8414 metadata plus `/oauth/*` endpoints. Native OAuth access tokens are accepted by `/mcp` alongside the emergency static bearer and, when present, a directly validated Cloudflare Access assertion.

The native OAuth server is not a password form. When that alternate flow is used, authorization is split into a protocol-stage request and a Cloudflare-authenticated consent stage:

`/oauth/authorize` -> signed short-lived authorization ticket -> `/oauth/login` -> validated Cloudflare identity + explicit approve/deny -> one-time authorization code -> `/oauth/token` -> resource-bound access token + rotating refresh token.

Exact parity therefore means preserving Cloudflare Managed OAuth as the public `/mcp` challenge while reproducing the AWS origin's full native OAuth subsystem behind it.

## Target public contract

Superfast will reproduce both externally observable contracts from the AWS reference:

1. **Public `/mcp` Managed OAuth contract:** unauthenticated MCP requests are intercepted by Cloudflare Access and challenged with `/.well-known/cloudflare-access-protected-resource/mcp`; that metadata advertises the Cloudflare Access authorization server.
2. **Origin/native OAuth contract:** the Superfast origin exposes the same native OAuth metadata and route shape as the AWS reference for fallback/alternate clients and rollback qualification.

The origin will expose:

- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-protected-resource/mcp`
- `GET /.well-known/oauth-authorization-server`
- `POST /oauth/register`
- `GET /oauth/authorize`
- `GET|POST /oauth/login`
- `POST /oauth/token`
- `POST /oauth/revoke`
- `/mcp` for MCP transport

The advertised native OAuth metadata will match the reference semantics:

- issuer = `https://superfast.heidiai.com.au`
- authorization endpoint = `/oauth/authorize`
- token endpoint = `/oauth/token`
- registration endpoint = `/oauth/register`
- revocation endpoint = `/oauth/revoke`
- response types = `code`
- response modes = `query`
- grants = `authorization_code`, `refresh_token`
- token endpoint auth = `none`
- PKCE = `S256`
- `client_id_metadata_document_supported = true`
- protected resource = `https://superfast.heidiai.com.au/mcp`
- scopes advertised only when configured; the default native scope is `mcp`

The **native** protected-resource metadata route will advertise the native Superfast issuer when native OAuth is enabled. An origin-direct RFC 6750 challenge will point to that path-specific RFC 9728 metadata URL and include configured native scopes when appropriate. On the public hostname, Cloudflare Access remains authoritative for unauthenticated `/mcp` and replaces that origin challenge with the Cloudflare Managed OAuth challenge, exactly as the live AWS reference does.

## Dynamic Client Registration and CIMD

### DCR

`POST /oauth/register` will follow the reference's public-client rules:

- request body limited to 64 KiB JSON
- `client_name` required and bounded
- one or more `redirect_uris`, with a bounded maximum
- HTTPS redirects allowed
- HTTP redirects allowed only for loopback hosts
- fragments and credential-bearing redirect URIs rejected
- `authorization_code` grant required
- `code` response type required
- only `token_endpoint_auth_method=none`
- `application_type` accepts `web` or `native`, defaulting to `web`
- response preserves normalized redirect URIs and application type
- response includes `client_id_issued_at`

DCR client IDs will be stateless signed client-metadata tokens, equivalent in purpose to the AWS `urn:cptr:oauth-client:<signed-jwt>` design. The Superfast prefix may be Superfast-specific, but validation rules and behavior must be parity-equivalent.

### Client ID Metadata Documents

HTTPS URL `client_id` values will be supported as Client ID Metadata Documents, matching the AWS reference's fail-closed SSRF protections:

- HTTPS only
- default port 443 only
- path required
- no URL credentials or fragment
- localhost and `.local` rejected
- DNS resolution performed before connection
- every resolved address must be public; loopback, RFC1918, link-local, CGNAT, documentation, multicast, reserved, and unique-local ranges rejected
- connection pinned to a validated resolved address while preserving TLS SNI
- short network timeout
- JSON content type required
- 32 KiB response limit
- `client_id` in the document must exactly equal the document URL
- bounded cache with bounded `max-age`

## Authorization and consent

`GET /oauth/authorize` will validate the request before any UI is rendered:

- `response_type=code`
- known DCR or CIMD client
- redirect URI exactly registered
- requested resource exactly equals the Superfast MCP resource
- PKCE `S256` required
- requested scopes must be supported

The validated request is serialized into a signed, short-lived authorization ticket. The browser is redirected to `/oauth/login?ticket=...`.

`/oauth/login` is the only interactive consent route in the **native fallback flow**. In production it must require a valid Cloudflare Access assertion before it can approve a native authorization ticket. No owner-password field will remain in that native flow.

The login identity is accepted only when:

- Access JWT signature validates via the configured JWKS
- algorithm is RS256
- issuer matches exactly
- audience includes the configured application AUD
- subject exists
- email exists and equals the configured owner email, case-insensitively
- optional custom resource/scope claims, if deliberately configured, match

GET renders the consent page. POST accepts `approve` or denial. The ticket is revalidated and the client's current registration is re-resolved before approval.

Approval issues a one-time authorization code tied to client ID, redirect URI, code challenge, resource, scope, subject, and email. Denial redirects to the client with `error=access_denied`.

Authorization redirects include the RFC 9207 `iss` parameter bound to the native OAuth issuer.

## Durable OAuth state

The reference uses SQLite WAL with synchronous durability. Superfast will use an embedded durable state database with equivalent transactional semantics. SQLite is the preferred implementation unless a Go-native alternative provides the same atomicity and restart behavior with lower risk.

The database will store only hashes of authorization codes and refresh tokens, never plaintext token values.

### Authorization codes

- cryptographically random opaque values
- approximately five-minute lifetime
- one-time consumption
- atomic consume/delete transaction
- survive process restart until expiry

### Refresh tokens

- cryptographically random opaque values
- approximately fourteen-day grant lifetime, matching the AWS reference default
- stored hashed with a token-family identifier
- successful refresh marks the presented token used and returns a replacement in the same family
- reuse of an already-used token revokes the entire family
- explicit revocation revokes the entire family
- expired or revoked values fail closed
- rotation is transactional

## Native access tokens

Access tokens will be signed JWTs equivalent to the AWS reference:

- HS256 using a dedicated native OAuth signing secret
- `token_use=access`
- issuer = native OAuth issuer
- audience = exact MCP resource
- subject = Cloudflare-authenticated owner subject
- `client_id`
- `scope`
- optional owner email
- `iat`, `nbf`, `exp`
- approximately 15-minute lifetime

`/mcp` accepts a native access token only when signature, issuer, audience, lifetime, token use, subject, and client identity validate. It must not accept a refresh token as an access token.

## Token endpoint

`POST /oauth/token` accepts only `application/x-www-form-urlencoded`, bounded to 64 KiB.

For `authorization_code`:

- client must resolve
- code and valid 43-128 character PKCE verifier required
- redirect URI and resource bindings must match the stored code
- authorization code is consumed one time
- PKCE comparison is constant-time where applicable
- returns a short-lived access token and a refresh token

For `refresh_token`:

- client must resolve
- resource must equal the Superfast MCP resource
- refresh token must be valid, unused, unexpired, and unrevoked
- token rotates on success
- reuse revokes the token family

Unsupported grants return a structured OAuth error. Token/error responses use `Cache-Control: no-store` and `Pragma: no-cache` where applicable. No token, code, verifier, assertion, owner identity credential, or authorization header may be logged.

## Revocation

`POST /oauth/revoke` will accept form-encoded `token`. Presenting a known refresh token revokes its entire family. Unknown tokens still return HTTP 200 with an empty JSON object, matching RFC-style non-disclosure behavior and the AWS reference.

## MCP authentication order

For `/mcp`, authentication order will remain parity-equivalent to the AWS reference:

1. validated `Cf-Access-Jwt-Assertion` when a Cloudflare Access config is enabled
2. configured static bearer for break-glass/origin qualification
3. native OAuth bearer access token
4. otherwise fail closed

A malformed/invalid Cloudflare assertion must not suppress a separately valid fallback bearer unless Cloudflare policy itself prevents that request from reaching the origin.

The eight MCP tools remain unchanged by this migration:

- `ping`
- `read_file`
- `write_file`
- `list_dir`
- `run_command`
- `git_status`
- `git_diff`
- `git_log`

## Cloudflare topology

The goal is to replicate the stable reference's **Managed-OAuth-first public edge plus native-origin fallback**, not replace one layer with the other.

For ChatGPT and other unauthenticated public `/mcp` clients, Cloudflare Access Managed OAuth remains the first authorization layer. The public 401 challenge must point to `/.well-known/cloudflare-access-protected-resource/mcp`, and that metadata must advertise the configured Cloudflare Access authorization server. Cloudflare performs public DCR/PKCE/authorization/token/refresh handling for that primary path and forwards a validated `Cf-Access-Jwt-Assertion` to the origin after successful authorization.

The origin simultaneously exposes the AWS-parity native metadata and `/oauth/*` subsystem for alternate/fallback clients, rollback qualification, and parity with the reference source. Native OAuth does not replace the public Managed OAuth challenge.

The exact Cloudflare application/rule configuration will be diffed against the stable `mcp.tnaprovider.com.au/mcp` application before mutation. Before edge changes, capture the current Superfast Access application/rules as rollback state. Desired behavior is verified from the public hostname and normalized against the stable hostname, not inferred solely from dashboard configuration.

## Configuration

Superfast will gain explicit configuration equivalent to the AWS reference:

- native OAuth issuer
- native OAuth resource
- native OAuth supported scopes
- native OAuth signing secret
- native OAuth durable-state database path
- Cloudflare Access issuer
- Cloudflare Access audience
- Cloudflare Access JWKS URL
- allowed owner email
- optional intentionally configured Cloudflare custom scopes
- static break-glass bearer

Production fails closed if native OAuth is enabled without a durable state path, a sufficiently strong signing secret, and Cloudflare Access identity validation for `/oauth/login`.

Secret values remain in protected environment files. Documentation and logs contain names/placeholders only.

## Service hardening

OAuth parity does not require changing the eight tool implementations, but the AWS reference demonstrates a stronger service boundary. During this migration the OAuth state database must be placed in a dedicated service-writable directory rather than an MCP-readable workspace root.

No migration step may move OAuth secrets or state beneath `/home/heidi` paths exposed through the MCP filesystem root. If the current service account cannot safely own the durable state directory without exposing it to MCP tools, deployment must use a protected system path with narrowly scoped systemd `ReadWritePaths` or an equivalent permission boundary.

A broader dedicated-service-user migration remains a separate security-hardening project unless it becomes necessary to isolate OAuth state safely.

## Observability

Keep sanitized production telemetry already introduced. For OAuth and MCP requests, log only fields needed to locate a failure, such as method, path, status, authentication mechanism/result, and a non-secret request correlation identifier when available.

Never log:

- query strings on OAuth routes
- authorization codes
- state
- PKCE values
- bearer/access/refresh tokens
- Cloudflare assertions
- cookies
- authorization headers
- form bodies
- client metadata document bodies beyond bounded validation errors

## Migration sequence

1. Freeze current `0.2.1` production binary, systemd drop-ins, Cloudflare Access application/rules, and protected environment as rollback state.
2. Implement AWS-parity native OAuth in Go behind tests while leaving current production untouched.
3. Add durable-state migration/config and provision a protected production state directory.
4. Qualify native OAuth locally and on the VM loopback: metadata, DCR, authorization ticket, Access-authenticated consent, code exchange, access token, refresh rotation, reuse-family revocation, explicit revocation, and MCP `tools/list`.
5. Deploy the new binary while the existing edge remains reversible.
6. Align Cloudflare Access/Managed OAuth settings field-for-field with the stable reference so public `/mcp` continues to advertise Cloudflare Managed OAuth, while the origin's native `/oauth/*` routes remain available behind the same hostname.
7. Run the public parity suite against both `mcp.tnaprovider.com.au` and `superfast.heidiai.com.au` and compare normalized behavior field-for-field.
8. Create a brand-new ChatGPT app/connector record so no frozen metadata or action snapshot from prior attempts is reused.
9. Complete OAuth and require the app to expose all eight tools without HTTP 424.
10. Retain rollback artifacts until the fresh connector has passed authorization, refresh, reconnect, and tool discovery.

## Required parity/acceptance tests

### Metadata and discovery

- public unauthenticated `/mcp` challenge points to Cloudflare's `/.well-known/cloudflare-access-protected-resource/mcp`, matching the live AWS reference
- Cloudflare protected-resource metadata returns the exact MCP resource and Cloudflare authorization server
- native `/.well-known/oauth-protected-resource[/mcp]` metadata independently returns the correct resource, native authorization server, bearer method, and configured native scopes
- native authorization metadata matches the AWS field set and route shape
- `response_modes_supported=["query"]`
- revocation endpoint advertised
- CIMD support advertised
- PKCE S256 advertised
- authorization-code and refresh-token grants advertised

### DCR and client metadata

- ChatGPT callback registration succeeds and preserves `application_type=web`
- native loopback client succeeds with `application_type=native`
- Claude/Gemini/Grok-style redirect shapes accepted as in AWS tests
- wrong auth method/grant/response type rejected
- unsafe redirects rejected
- signed DCR client ID resolves and rejects tampering
- CIMD validates public documents and rejects SSRF/private-address cases

### Authorization

- valid authorization request produces signed login ticket redirect
- invalid resource, redirect, client, scope, PKCE, or response type rejected
- `/oauth/login` fails closed without valid Cloudflare identity in production
- allowed Cloudflare owner gets consent UI
- deny returns `access_denied`
- approve returns code/state/`iss`
- registration changes between authorize and consent are detected

### Token state

- authorization codes are one-time and expire
- authorization code binding covers client, redirect, resource, and PKCE
- access token has correct issuer/audience/subject/client/scope/use/lifetime
- refresh token always issued after successful code exchange
- refresh rotates
- reuse revokes family
- explicit revocation revokes family
- refresh state survives service restart
- no credential/grant material logged

### MCP

- native access token authenticates `/mcp`
- wrong issuer/audience/expiry/nbf/token use/subject/client fails
- Cloudflare assertion path remains valid when intentionally used
- static bearer remains valid for break-glass qualification
- authenticated `server/discover` is stable
- authenticated `tools/list` returns exactly the eight Superfast tools
- supported MCP protocol versions remain unchanged

### Public edge and ChatGPT

- public `/mcp` challenge points to Cloudflare Managed OAuth metadata exactly as the stable reference does
- default non-browser HTTP clients receive normal OAuth responses, not Cloudflare 1010
- Cloudflare Managed OAuth DCR/authorization/token/refresh behavior matches the normalized stable reference
- native `/oauth/register`, `/oauth/authorize`, `/oauth/login`, `/oauth/token`, and `/oauth/revoke` independently match the normalized AWS origin implementation
- new ChatGPT connector completes OAuth
- callback returns success rather than 424
- action scan shows all eight tools
- refresh/reconnect works after initial authorization

## Rollback

Rollback must be possible independently at both layers:

- origin rollback: restore the preserved pre-parity binary and systemd/env snapshot
- edge rollback: restore the captured Cloudflare Access/Managed OAuth configuration

The new OAuth database is additive and must not require destructive rollback. Old native/Managed OAuth credentials should not be deleted during qualification. Once the parity connector has been proven stable, stale connector records and obsolete auth configuration can be retired in a separate reviewed cleanup.

## Non-goals

This migration does not redesign the MCP tool set, sandbox `run_command`, narrow `/home/heidi` filesystem roots, migrate the whole service to a dedicated Unix account, or implement unrelated UI features. Those remain important hardening items but are independent of reproducing the stable OAuth implementation.
