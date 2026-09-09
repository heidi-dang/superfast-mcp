package mcpx

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/heidi-dang/superfast-mcp/internal/config"
	"github.com/heidi-dang/superfast-mcp/internal/fs"
	"github.com/heidi-dang/superfast-mcp/internal/git"
	oauthserver "github.com/heidi-dang/superfast-mcp/internal/oauth"
	"github.com/heidi-dang/superfast-mcp/internal/roots"
	"github.com/heidi-dang/superfast-mcp/internal/shell"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewServer(cfg *config.Config) (*mcp.Server, error) {
	rootSet, err := roots.New(cfg.Roots)
	if err != nil {
		return nil, err
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "superfast-mcp",
		Version: cfg.Version,
	}, nil)

	fsSvc := fs.New(rootSet)
	shellSvc := shell.New(rootSet)
	gitSvc := git.New(rootSet)

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

	return server, nil
}

func RunStdio(cfg *config.Config) error {
	server, err := NewServer(cfg)
	if err != nil {
		return err
	}
	slog.Info("superfast-mcp starting on stdio", "version", cfg.Version, "roots", cfg.Roots)
	return server.Run(context.Background(), &mcp.StdioTransport{})
}

func NewHTTPHandler(cfg *config.Config) (http.Handler, error) {
	if cfg.AuthToken == "" && !cfg.AllowUnauthenticatedHTTP {
		return nil, fmt.Errorf("HTTP MCP requires bearer authentication; configure SUPERFAST_AUTH_TOKEN or explicitly allow unauthenticated HTTP")
	}
	server, err := NewServer(cfg)
	if err != nil {
		return nil, err
	}
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	limitedMCP := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
		}
		mcpHandler.ServeHTTP(w, r)
	})
	protectedMCP := bearerAuth(cfg.AuthToken, limitedMCP)

	mux := http.NewServeMux()
	if cfg.AuthToken != "" && cfg.PublicURL != "" {
		issuer := strings.TrimRight(cfg.PublicURL, "/")
		oauthServer, err := oauthserver.New(issuer, issuer+"/mcp", cfg.AuthToken, cfg.OAuthOwnerPassword)
		if err != nil {
			return nil, err
		}
		oauthServer.RegisterRoutes(mux)
		protectedMCP = bearerAuthWithOAuth(cfg.AuthToken, oauthServer, limitedMCP)
	}
	mux.Handle("/mcp", protectedMCP)
	mux.Handle("/mcp/", protectedMCP)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": cfg.Version})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "superfast-mcp %s\nMCP endpoint: /mcp\nHealth: /health\n", cfg.Version)
	})
	return mux, nil
}

func RunHTTP(cfg *config.Config) error {
	if strings.TrimSpace(cfg.HTTPAddr) == "" {
		return fmt.Errorf("HTTP listen address must not be empty")
	}
	handler, err := NewHTTPHandler(cfg)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	public := cfg.PublicURL
	if public == "" {
		host := cfg.HTTPAddr
		if strings.HasPrefix(host, ":") {
			host = "localhost" + host
		}
		public = "http://" + host
	}
	slog.Info("superfast-mcp listening", "version", cfg.Version, "addr", cfg.HTTPAddr, "public", public+"/mcp", "roots", cfg.Roots, "authenticated", cfg.AuthToken != "")

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-signalCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func bearerAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		valid := len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && subtle.ConstantTimeCompare([]byte(parts[1]), []byte(token)) == 1
		if !valid {
			w.Header().Set("WWW-Authenticate", `Bearer realm="superfast-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerAuthWithOAuth(token string, oauthServer *oauthserver.Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		valid := len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") &&
			(subtle.ConstantTimeCompare([]byte(parts[1]), []byte(token)) == 1 || oauthServer.VerifyAccessToken(parts[1]))
		if !valid {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="superfast-mcp", resource_metadata=%q, scope="mcp"`, oauthServer.ResourceMetadataURL()))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func Run(cfg *config.Config) error {
	if cfg.StdioOnly {
		return RunStdio(cfg)
	}
	if cfg.HTTPOnly {
		return RunHTTP(cfg)
	}
	if strings.TrimSpace(cfg.HTTPAddr) == "" || isStdioPipe() {
		return RunStdio(cfg)
	}
	return RunHTTP(cfg)
}

func isStdioPipe() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) == 0
}
