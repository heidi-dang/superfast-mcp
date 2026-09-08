package mcpx

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/heidi-dang/superfast-mcp/internal/config"
	"github.com/heidi-dang/superfast-mcp/internal/fs"
	"github.com/heidi-dang/superfast-mcp/internal/git"
	"github.com/heidi-dang/superfast-mcp/internal/shell"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewServer(cfg *config.Config) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "superfast-mcp",
		Version: cfg.Version,
	}, nil)

	fsSvc := fs.New(cfg.Roots)
	shellSvc := shell.New(cfg.Roots)
	gitSvc := git.New(cfg.Roots)

	type pingArgs struct{}
	type pingOut struct {
		OK      bool     `json:"ok"`
		Version string   `json:"version"`
		Roots   []string `json:"roots"`
		Time    string   `json:"time"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "ping",
		Description: "Health check. Returns server version, configured workspace roots, and current time.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ pingArgs) (*mcp.CallToolResult, pingOut, error) {
		out := pingOut{OK: true, Version: cfg.Version, Roots: fsSvc.Roots(), Time: time.Now().UTC().Format(time.RFC3339)}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("superfast-mcp %s ok roots=%v", cfg.Version, out.Roots)}},
		}, out, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_file",
		Description: "Read a text file under the configured workspace roots. Returns content (capped at 512KiB).",
	}, fsSvc.ReadFile)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "write_file",
		Description: "Write a text file under the configured workspace roots. Creates parent directories as needed.",
	}, fsSvc.WriteFile)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_dir",
		Description: "List directory entries under the configured workspace roots.",
	}, fsSvc.ListDir)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_command",
		Description: "Run a shell command (bash -lc) under a workspace root. Captures stdout/stderr with timeout. Prefer this for one-shot commands; use terminal_* tools (coming soon) for interactive PTY sessions.",
	}, shellSvc.Run)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "git_status",
		Description: "Run git status --porcelain -b in a workspace root.",
	}, gitSvc.Status)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "git_diff",
		Description: "Run git diff (optionally --cached) in a workspace root. Output capped at 100KiB.",
	}, gitSvc.Diff)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "git_log",
		Description: "Show recent git log --oneline (default 10, max 50).",
	}, gitSvc.Log)

	return server
}

func RunStdio(cfg *config.Config) error {
	server := NewServer(cfg)
	log.Printf("superfast-mcp %s starting on stdio roots=%v", cfg.Version, cfg.Roots)
	return server.Run(context.Background(), &mcp.StdioTransport{})
}

func RunHTTP(cfg *config.Config) error {
	server := NewServer(cfg)
	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.Handle("/mcp/", handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"version":%q,"roots":%q}`, cfg.Version, strings.Join(cfg.Roots, ","))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "superfast-mcp %s\nMCP endpoint: /mcp\nHealth: /health\n", cfg.Version)
	})

	addr := cfg.HTTPAddr
	if addr == "" {
		addr = ":8787"
	}
	public := cfg.PublicURL
	if public == "" {
		public = "http://localhost" + addr
	}
	log.Printf("superfast-mcp %s listening on %s  (public %s/mcp)  roots=%v", cfg.Version, addr, public, cfg.Roots)
	return http.ListenAndServe(addr, mux)
}

func Run(cfg *config.Config) error {
	if cfg.StdioOnly {
		return RunStdio(cfg)
	}
	if cfg.HTTPOnly || cfg.HTTPAddr != "" {
		if isStdioAttached() && !cfg.HTTPOnly {
			return RunStdio(cfg)
		}
		return RunHTTP(cfg)
	}
	return RunStdio(cfg)
}

func isStdioAttached() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}
