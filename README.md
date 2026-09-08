# superfast-mcp

**Ultra-low-latency Go MCP server + live terminal UI** for ChatGPT, Grok, and Claude.

Local computer use (PTY, filesystem, git, coding tools) with real-time streaming into an MCP App terminal surface. Designed to sit on an existing DNS domain and deliver sub-millisecond local tool latency while keeping the public control plane thin.

> Inspired by the production patterns in [chatgpt-terminal-plugin](https://github.com/heidi-dang/chatgpt-terminal-plugin) (persistent PTY, short-lived SSE for the UI, device identity, bounded tools). Re-implemented in Go for maximum speed and a single static binary.

## Goals

- **Speed first** — single Go binary, zero Node/Python runtime on the hot path, persistent PTY + browser context, minimal allocations.
- **Cross-host** — works with Claude Desktop / Cursor (stdio), ChatGPT & Grok (HTTPS Streamable HTTP on your domain).
- **Live UI** — every shell line, git output, file edit, and computer-use action streams directly into the MCP App terminal widget in real time.
- **Secure by default** — rooted workspaces, execution profiles, device identity, short-lived UI stream tokens, no long-lived secrets in the binary.

## High-level architecture

```text
ChatGPT / Grok / Claude
        │
        │  MCP Streamable HTTP (HTTPS on your DNS)
        │  or stdio (Claude Desktop / Cursor)
        ▼
┌───────────────────────────────────────┐
│  superfast-mcp (Go single binary)     │
│                                       │
│  • MCP tools (2026-07-28 stateless)   │
│  • Persistent PTY manager             │
│  • Filesystem / git / apply_patch     │
│  • Computer-use (CDP)                 │
│  • Short-lived SSE for Terminal UI    │
│  • Optional local-agent WebSocket     │
└───────────────────┬───────────────────┘
                    │
                    ▼
          local shell / workspace
```

Two output paths (same design as chatgpt-terminal-plugin):

1. **Model path** — bounded `terminal_read` / tool results with monotonic cursors (authoritative context for the LLM).
2. **UI path** — short-lived, session-scoped SSE capability that feeds the MCP App Terminal UI only. The browser never holds the primary OAuth bearer.

## Current tools (Phase 0 + 1)

| Tool | Description |
|------|-------------|
| `ping` | Health, version, roots |
| `read_file` | Rooted text read (512KiB cap) |
| `write_file` | Rooted write + mkdir |
| `list_dir` | Rooted directory listing |
| `run_command` | `bash -lc` with timeout + capture |
| `git_status` | `git status --porcelain -b` |
| `git_diff` | `git diff` / `--cached` |
| `git_log` | recent `git log --oneline` |

## Quick start

```bash
git clone https://github.com/heidi-dang/superfast-mcp.git
cd superfast-mcp
go build -o superfast-mcp ./cmd/superfast-mcp

# Claude Desktop / Cursor (stdio)
./superfast-mcp --stdio-only --roots /path/to/code

# ChatGPT / Grok (HTTPS on your domain)
./superfast-mcp --http :8787 --public-url https://mcp.yourdomain.com --roots /path/to/code
# then put Caddy (see deploy/Caddyfile.example) in front of :8787
```

Claude Desktop config:

```json
{
  "mcpServers": {
    "superfast": {
      "command": "/path/to/superfast-mcp",
      "args": ["--stdio-only", "--roots", "/Users/you/code"]
    }
  }
}
```

ChatGPT: Developer Mode → Create custom connector → `https://mcp.yourdomain.com/mcp`

## Repository layout

```text
superfast-mcp/
├── cmd/superfast-mcp/     # main binary
├── internal/
│   ├── mcp/               # dual transport + tool registration
│   ├── fs/                # rooted filesystem
│   ├── shell/             # run_command
│   ├── git/               # status/diff/log
│   └── config/            # flags
├── deploy/
│   ├── Caddyfile.example
│   └── env.example
├── go.mod
└── README.md
```

## Implementation plan

### Phase 0 — Foundations ✅
- Go module + official `github.com/modelcontextprotocol/go-sdk` v1.7.0 (2026-07-28).
- Dual transport: stdio + Streamable HTTP (`Stateless: true`).
- `ping` + `/health`.

### Phase 1 — Core local tools ✅
- Rooted `read_file` / `write_file` / `list_dir`.
- `run_command` with timeout.
- `git_status` / `git_diff` / `git_log`.

### Phase 2 — Persistent PTY + live streaming (next)
- PTY manager, monotonic events, `terminal_*` tools.
- Short-lived SSE for MCP App UI (parity with chatgpt-terminal-plugin).

### Phase 3 — MCP App Terminal UI
- Static UI embedded via `//go:embed`, live stream rendering.

### Phase 4 — Computer use + advanced coding
- Long-lived CDP, apply_patch, optional LSP.

### Phase 5 — Production hardening
- Device identity, profiles, audit, systemd, install script.

## Status

**Phase 0 + Phase 1 complete.** Dual-transport Go binary with rooted filesystem, shell, and git tools is in `main`. Next: Phase 2 PTY + live Terminal UI streaming.

## License

TBD (recommend MIT or Apache-2.0).
