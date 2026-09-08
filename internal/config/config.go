package config

import (
	"flag"
	"os"
	"strings"
)

type Config struct {
	HTTPAddr  string
	PublicURL string
	Roots     []string
	StdioOnly bool
	HTTPOnly  bool
	LogJSON   bool
	Version   string
}

func Parse() *Config {
	c := &Config{Version: "0.1.0"}
	var roots string
	flag.StringVar(&c.HTTPAddr, "http", ":8787", "HTTP listen address for Streamable HTTP (empty to disable)")
	flag.StringVar(&c.PublicURL, "public-url", "", "Public base URL (e.g. https://mcp.example.com) for ChatGPT/Grok connectors")
	flag.StringVar(&roots, "roots", "", "Comma-separated workspace roots (required for fs/shell tools)")
	flag.BoolVar(&c.StdioOnly, "stdio-only", false, "Run only stdio transport (Claude Desktop / Cursor)")
	flag.BoolVar(&c.HTTPOnly, "http-only", false, "Run only HTTP transport")
	flag.BoolVar(&c.LogJSON, "log-json", false, "JSON structured logs")
	flag.Parse()

	if roots != "" {
		for _, r := range strings.Split(roots, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				c.Roots = append(c.Roots, r)
			}
		}
	}
	if len(c.Roots) == 0 {
		if wd, err := os.Getwd(); err == nil {
			c.Roots = []string{wd}
		}
	}
	return c
}
