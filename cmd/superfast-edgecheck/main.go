package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/heidi-dang/superfast-mcp/internal/edgecheck"
)

const (
	defaultMCPURL      = "https://superfast.heidiai.com.au/mcp"
	defaultRedirectURL = "https://chatgpt.com/connector_platform_oauth_redirect"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "superfast edge verification failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	mcpURL := envOrDefault("SUPERFAST_EDGE_MCP_URL", defaultMCPURL)
	redirect := envOrDefault("SUPERFAST_EDGE_CHATGPT_REDIRECT", defaultRedirectURL)
	accessToken := strings.TrimSpace(os.Getenv("SUPERFAST_EDGE_ACCESS_TOKEN"))
	timeoutRaw := envOrDefault("SUPERFAST_EDGE_TIMEOUT", "10s")
	timeout, err := time.ParseDuration(timeoutRaw)
	if err != nil || timeout <= 0 {
		return fmt.Errorf("SUPERFAST_EDGE_TIMEOUT must be a positive duration")
	}

	result, err := edgecheck.Check(context.Background(), nil, edgecheck.Options{
		MCPURL:          mcpURL,
		ChatGPTRedirect: redirect,
		AccessToken:     accessToken,
		Timeout:         timeout,
	})
	if err != nil {
		return err
	}
	tools := "unchecked"
	if result.ToolCount >= 0 {
		tools = strconv.Itoa(result.ToolCount)
	}
	fmt.Printf("superfast edge verified: auth=%s auth_host=%s tools=%s\n", result.AuthMode, result.AuthorizationHost, tools)
	return nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
