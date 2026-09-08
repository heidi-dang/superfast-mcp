package main

import (
	"log"
	"os"

	"github.com/heidi-dang/superfast-mcp/internal/config"
	mcpx "github.com/heidi-dang/superfast-mcp/internal/mcp"
)

func main() {
	cfg := config.Parse()
	if err := mcpx.Run(cfg); err != nil {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
}
