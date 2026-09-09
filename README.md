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

Remote HTTP fails closed unless authentication is configured or unauthenticated mode is explicitly requested. When `SUPERFAST_PUBLIC_URL` and `SUPERFAST_AUTH_TOKEN` are both set, the server automatically exposes MCP-compatible OAuth 2.1 discovery, Dynamic Client Registration, PKCE authorization-code flow, and refresh tokens. The static bearer token remains available as a break-glass credential.

```bash
export SUPERFAST_HTTP=127.0.0.1:8787
export SUPERFAST_HTTP_ONLY=true
export SUPERFAST_PUBLIC_URL=https://mcp.example.com
export SUPERFAST_ROOTS=/path/to/code
export SUPERFAST_AUTH_TOKEN="$(openssl rand -hex 32)"

./superfast-mcp
```

Put a TLS reverse proxy such as Caddy in front of `127.0.0.1:8787`; see `deploy/Caddyfile.example`. OAuth-capable MCP clients discover the protected resource and authorization server from the standard `/.well-known/` endpoints, register as public clients, and use PKCE-S256. The authorization page requires the server owner's derived authorization password before issuing a code. Access tokens are resource-bound and expire after one hour; refresh tokens are issued when `offline_access` is requested.

Static clients can still send `Authorization: Bearer <token>` directly. For production, keep the master token outside shell history and source control. `--auth-token-file` or `SUPERFAST_AUTH_TOKEN_FILE` can load it from a permission-restricted file. `/health` intentionally remains public and reports only health/version; `/mcp` is protected.

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
- `SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP`

See `deploy/env.example` for a production-oriented baseline.

## Repository layout

```text
superfast-mcp/
├── cmd/superfast-mcp/
├── internal/
│   ├── config/
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
