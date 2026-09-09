package main

import (
	"log/slog"
	"os"

	"github.com/heidi-dang/superfast-mcp/internal/config"
	mcpx "github.com/heidi-dang/superfast-mcp/internal/mcp"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	if cfg.LogJSON {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	}
	if err := mcpx.Run(cfg); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
