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

## Repository layout (planned)

```text
superfast-mcp/
├── cmd/
│   └── superfast-mcp/          # main binary
├── internal/
│   ├── mcp/                    # MCP server, tools, discover, Streamable HTTP + stdio
│   ├── pty/                    # persistent PTY sessions, resize, interrupt, streaming
│   ├── fs/                     # rooted filesystem tools
│   ├── git/                    # thin git wrappers
│   ├── computer/               # CDP browser automation
│   ├── stream/                 # short-lived SSE tokens + event fan-out
│   ├── identity/               # device keys, enrollment, profiles
│   └── ui/                     # embedded Terminal UI assets (MCP App)
├── web/
│   └── terminal/               # static Terminal UI (replicated live streaming UX)
├── deploy/
│   ├── Caddyfile.example
│   ├── systemd/
│   └── env.example
├── docs/
│   ├── architecture.md
│   ├── protocol.md
│   └── security.md
├── go.mod
└── README.md
```

## Implementation plan

### Phase 0 — Foundations (1–2 days)
- Go module + official `github.com/modelcontextprotocol/go-sdk` (2026-07-28).
- Dual transport: stdio + Streamable HTTP on `:8787` (or configurable).
- Basic `tools/list` + a couple of no-op tools to verify Claude Desktop and ChatGPT connector reachability on the existing DNS domain.
- Health + metrics endpoints.

### Phase 1 — Core local tools (fast path)
- **Filesystem**: rooted `read_file`, `write_file`, `apply_patch`, `list_dir`, `search` with canonical-path + symlink checks.
- **Shell**: `run_command` with timeout, cwd, env allowlist, streaming stdout/stderr.
- **Git**: `git_status`, `git_diff`, `git_log`, `git_commit` (thin, safe wrappers).
- All tool results include structured content + short text summary.

### Phase 2 — Persistent PTY + live streaming (UI parity)
- PTY manager (creack/pty or equivalent) with session lifecycle, resize, interrupt (SIGINT).
- Monotonic event sequence + bounded ring buffer.
- `terminal_start` / `terminal_read` / `terminal_write` / `terminal_close` tools.
- Short-lived SSE capability (`stream_token`) for the MCP App UI exactly as in chatgpt-terminal-plugin.
- Replicate the Terminal UI look-and-feel and streaming behaviour from `packages/terminal-ui` (xterm.js or lightweight equivalent, live line-by-line output).

### Phase 3 — MCP App Terminal UI
- Static-first HTML/JS bundle served as `ui://terminal/...` resource.
- Receives only the short-lived SSE token; never the main OAuth bearer.
- Live rendering of every PTY event, command result, git output, and computer-use action.
- Optional split-pane: terminal + file diff / screenshot.

### Phase 4 — Computer use + advanced coding
- Persistent Chromium via CDP (chromedp or similar).
- Tools: `screenshot`, `click`, `type`, `scroll`, `key`.
- Optional LSP bridge for symbol-aware edits.

### Phase 5 — Production hardening
- Device identity (Ed25519), enrollment, rotation, revocation.
- Execution profiles: `read-only` | `developer` | `owner-full`.
- Audit log + transcript with redaction.
- Caddy / systemd examples that bind to the existing DNS domain.
- One-command install + smoke tests against ChatGPT custom connector and Claude Desktop.

## Connecting to hosts

### Claude Desktop / Cursor (stdio — lowest latency)
```json
{
  "mcpServers": {
    "superfast": {
      "command": "/usr/local/bin/superfast-mcp",
      "args": ["--roots", "/Users/you/code,/Users/you/projects"]
    }
  }
}
```

### ChatGPT / Grok (HTTPS on your domain)
1. Run the binary with `--http :8787 --public-url https://mcp.yourdomain.com`.
2. Terminate TLS with Caddy (or your existing edge) so the public origin is `https://mcp.yourdomain.com/mcp`.
3. In ChatGPT: Developer Mode → Create custom connector → paste the HTTPS URL → complete OAuth if configured.
4. The same binary serves the Terminal UI resource; ChatGPT will render the live surface when the model calls `terminal_surface`.

No extra Node process is required on the hot path.

## Security model (inherited + improved)

- Workspace roots are mandatory; every path is canonicalised and checked.
- Shell and write tools respect the more restrictive of server-side and agent-side execution profiles.
- UI stream tokens are short-lived, session-bound, and single-use for the browser widget.
- Device keys never leave the local machine; the public control plane only stores public keys + enrollment metadata.
- Destructive tools are clearly marked so hosts can require user confirmation.

## Suggested architecture improvements over chatgpt-terminal-plugin

| Area | Suggestion |
|------|------------|
| Runtime | Single static Go binary instead of Node monorepo → faster cold start, lower memory, easier distribution. |
| Transport | Keep dual stdio + Streamable HTTP in one process; avoid a separate local-agent WebSocket unless multi-machine enrollment is required. |
| Streaming | Use Go channels + ring buffer for PTY events; push both model cursor and UI SSE from the same source of truth. |
| UI | Embed the Terminal UI assets with `//go:embed` so the binary is self-contained. |
| Computer use | Keep a long-lived CDP session; never relaunch Chromium per tool call. |
| Multi-replica | Add optional Redis / NATS for session routing if you later need HA behind a load balancer. |
| Observability | Native Prometheus metrics + structured JSON logs from day one. |
| Sandbox | Optional bubblewrap / Landlock profile for the developer execution mode on Linux. |
| Diff UX | Stream unified diffs into the Terminal UI side-by-side with the PTY for coding sessions. |

## Status

Repository just created. Implementation follows the phased plan above. First milestone: dual-transport Go binary that Claude Desktop and a ChatGPT custom connector on the existing DNS domain can both reach.

## License

TBD (recommend MIT or Apache-2.0).
