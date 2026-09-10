# superfast-mcp

Fast Go MCP server for local filesystem, shell, and Git operations. It supports stdio for local MCP clients and stateless Streamable HTTP for remote clients.

The repository currently implements Phase 0/1 tooling. The terminal UI under `web/terminal` is a preview surface; persistent PTY streaming and computer-use are not implemented yet.

## Current tools

| Tool | Description |
|---|---|
| `ping` | Health, version, configured roots |
| `read_file` | Rooted regular-file read, capped at 512 KiB |
| `write_file` | Rooted write + parent directory creation, capped at 2 MiB |
| `list_dir` | Rooted directory listing, capped at 500 entries |
| `run_command` | `bash -lc` with bounded output and timeout |
| `git_status` | bounded `git status --porcelain -b` |
| `git_diff` | bounded `git diff` / `--cached` |
| `git_log` | recent bounded `git log --oneline` |

Filesystem and Git paths are constrained to configured roots and use rooted filesystem operations to prevent symlink traversal. `run_command` validates its initial working directory, but the shell command itself is intentionally **not a sandbox**: it executes with the OS permissions of the server process.

## Requirements

- Go 1.25.12 or newer. The minimum includes security fixes required by the rooted filesystem implementation.
- `bash` for `run_command`.
- `git` for Git tools.

## Build

```bash
git clone https://github.com/heidi-dang/superfast-mcp.git
cd superfast-mcp
go build -trimpath -o superfast-mcp ./cmd/superfast-mcp
```

## Local stdio

```bash
./superfast-mcp --stdio-only --roots /path/to/code
```

Example local MCP client configuration:

```json
{
  "mcpServers": {
    "superfast": {
      "command": "/path/to/superfast-mcp",
      "args": ["--stdio-only", "--roots", "/path/to/code"]
    }
  }
}
```

## Remote HTTP

Remote HTTP fails closed unless authentication is configured or unauthenticated mode is explicitly requested. Production uses the same dual-layer OAuth architecture as the stable AWS reference.

### Cloudflare Managed OAuth — public ChatGPT path

Cloudflare Access owns the public OAuth flow and the externally observed `/mcp` `WWW-Authenticate` challenge. The Go origin does not trust the forwarded Cloudflare header by itself: it validates `Cf-Access-Jwt-Assertion` with the configured Access issuer, application audience, owner identity, JWKS, signature, and JWT time claims, plus resource/scope restrictions only when those claims are intentionally used. The existing static bearer remains available as an origin/break-glass path.

Example origin configuration, using placeholders only:

```bash
export SUPERFAST_HTTP=127.0.0.1:8787
export SUPERFAST_HTTP_ONLY=true
export SUPERFAST_PUBLIC_URL=https://mcp.example.com
export SUPERFAST_ROOTS=/path/to/code
export SUPERFAST_AUTH_TOKEN_FILE=/run/secrets/superfast-mcp-token
export SUPERFAST_CF_ACCESS_ISSUER=https://your-team.cloudflareaccess.com
export SUPERFAST_CF_ACCESS_AUDIENCE=replace-with-access-application-aud
export SUPERFAST_CF_ACCESS_ALLOWED_EMAIL=owner@example.com

./superfast-mcp
```

`SUPERFAST_CF_ACCESS_JWKS_URL` is optional and defaults to `<issuer>/cdn-cgi/access/certs`. `SUPERFAST_CF_ACCESS_REQUIRED_SCOPES` is also optional; leave it unset for standard Cloudflare Access Managed OAuth assertions because Access application JWTs do not normally contain OAuth scope claims. Only configure it when your deployment intentionally supplies a trusted custom `scope` claim. Keep all real Access identifiers, identities, and credentials outside source control.

Qualify the public Cloudflare Managed OAuth contract without printing credentials:

```bash
SUPERFAST_EDGE_MCP_URL=https://superfast.heidiai.com.au/mcp \
  go run ./cmd/superfast-edgecheck
```

Set `SUPERFAST_EDGE_ACCESS_TOKEN` only when performing the authenticated phase; the command uses it solely as a Bearer header and never prints it. A successful authenticated check requires exactly the eight tools documented above.

### Native OAuth fallback — AWS parity

The origin also exposes an independent native OAuth 2.1 fallback at `/oauth/{register,authorize,login,token,revoke}`. Enable it with `SUPERFAST_NATIVE_OAUTH_SECRET` and `SUPERFAST_NATIVE_OAUTH_DB` plus the complete Cloudflare Access settings above. The native flow uses signed DCR client metadata, PKCE S256, resource-bound access JWTs, durable one-time authorization codes, rotating refresh-token families, revocation, and Client ID Metadata Documents.

`SUPERFAST_NATIVE_OAUTH_ADVERTISE` controls whether the origin also publishes native discovery metadata at `/.well-known/oauth-protected-resource[/mcp]` and `/.well-known/oauth-authorization-server`. When native OAuth is configured for ChatGPT, set it to `true` and keep those paths publicly routed to the origin. Cloudflare Access can still own the `/mcp` challenge, but hiding the standard RFC 9728/8414 endpoints breaks clients that probe native OAuth discovery before authorization.

`/oauth/login` does not use the legacy owner-password form. It requires a valid Cloudflare Access assertion and then presents explicit approve/deny consent. Store `SUPERFAST_NATIVE_OAUTH_DB` under a protected service-writable path such as `/var/lib/superfast-mcp/oauth/state.db`, never beneath an MCP-readable workspace root. Keep `SUPERFAST_NATIVE_OAUTH_SECRET` outside source control.

Qualify the native origin contract independently by setting `SUPERFAST_EDGE_NATIVE_ORIGIN` when running `superfast-edgecheck`; the public Managed OAuth check remains unchanged.

Static clients can still send `Authorization: Bearer <token>` directly. Keep the master token outside shell history and source control; prefer `--auth-token-file` or `SUPERFAST_AUTH_TOKEN_FILE` with a permission-restricted file. `/health` intentionally remains public and reports only health/version; `/mcp` is protected.

`--allow-unauthenticated-http` / `SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP=true` is an explicit escape hatch for a separately protected trusted network or proxy. Do not use it on a directly reachable host.

## Environment

Supported variables:

- `SUPERFAST_HTTP`
- `SUPERFAST_PUBLIC_URL`
- `SUPERFAST_ROOTS`
- `SUPERFAST_STDIO_ONLY`
- `SUPERFAST_HTTP_ONLY`
- `SUPERFAST_LOG_JSON`
- `SUPERFAST_AUTH_TOKEN`
- `SUPERFAST_AUTH_TOKEN_FILE`
- `SUPERFAST_OAUTH_OWNER_PASSWORD` (deprecated compatibility setting)
- `SUPERFAST_NATIVE_OAUTH_ISSUER`
- `SUPERFAST_NATIVE_OAUTH_RESOURCE`
- `SUPERFAST_NATIVE_OAUTH_SCOPES`
- `SUPERFAST_NATIVE_OAUTH_SECRET`
- `SUPERFAST_NATIVE_OAUTH_DB`
- `SUPERFAST_NATIVE_OAUTH_ADVERTISE` (set `true` when native OAuth serves ChatGPT discovery)
- `SUPERFAST_CF_ACCESS_ISSUER`
- `SUPERFAST_CF_ACCESS_AUDIENCE`
- `SUPERFAST_CF_ACCESS_ALLOWED_EMAIL`
- `SUPERFAST_CF_ACCESS_JWKS_URL`
- `SUPERFAST_CF_ACCESS_REQUIRED_SCOPES`
- `SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP`

See `deploy/env.example` for a production-oriented baseline.

## Repository layout

```text
superfast-mcp/
├── cmd/
│   ├── superfast-mcp/
│   └── superfast-edgecheck/
├── internal/
│   ├── access/
│   ├── config/
│   ├── edgecheck/
│   ├── fs/
│   ├── git/
│   ├── limitio/
│   ├── mcp/
│   ├── roots/
│   └── shell/
├── deploy/
├── web/terminal/
├── go.mod
├── go.sum
└── README.md
```

## Roadmap

- **Phase 0 — Foundations:** complete; dual transport, `ping`, `/health`.
- **Phase 1 — Core local tools:** complete; rooted filesystem, shell, and Git tools.
- **Phase 2 — Persistent PTY + live streaming:** next.
- **Phase 3 — MCP App terminal UI:** embed and connect the preview UI to live streams.
- **Phase 4 — Computer use + advanced coding:** CDP, patching, optional LSP.
- **Phase 5 — Additional production hardening:** richer identity/policy, audit, installer/systemd packaging.

## License

TBD.
