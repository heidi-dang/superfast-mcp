package config

import (
	"os"
	"path/filepath"
	"testing"
)

func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestParseArgsDefaultsHTTPToLoopback(t *testing.T) {
	cfg, err := ParseArgs([]string{"--allow-unauthenticated-http"}, envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != "127.0.0.1:8787" {
		t.Fatalf("HTTPAddr = %q, want loopback default", cfg.HTTPAddr)
	}
}

func TestParseArgsReadsDocumentedEnvironment(t *testing.T) {
	root := t.TempDir()
	cfg, err := ParseArgs(nil, envMap(map[string]string{
		"SUPERFAST_HTTP":       "127.0.0.1:9999",
		"SUPERFAST_PUBLIC_URL": "https://mcp.example.com/",
		"SUPERFAST_ROOTS":      root,
		"SUPERFAST_HTTP_ONLY":  "true",
		"SUPERFAST_AUTH_TOKEN": "secret",
		"SUPERFAST_LOG_JSON":   "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9999" || cfg.PublicURL != "https://mcp.example.com" || !cfg.HTTPOnly || !cfg.LogJSON || cfg.AuthToken != "secret" {
		t.Fatalf("environment was not applied: %#v", cfg)
	}
	if len(cfg.Roots) != 1 || cfg.Roots[0] != root {
		t.Fatalf("roots = %#v", cfg.Roots)
	}
}

func TestParseArgsReadsOAuthOwnerPasswordEnvironment(t *testing.T) {
	cfg, err := ParseArgs([]string{"--allow-unauthenticated-http"}, envMap(map[string]string{
		"SUPERFAST_OAUTH_OWNER_PASSWORD": "owner-secret",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthOwnerPassword != "owner-secret" {
		t.Fatalf("OAuthOwnerPassword = %q, want owner-secret", cfg.OAuthOwnerPassword)
	}
}

func TestParseArgsRejectsConflictingTransports(t *testing.T) {
	_, err := ParseArgs([]string{"--stdio-only", "--http-only"}, envMap(map[string]string{"SUPERFAST_AUTH_TOKEN": "secret"}))
	if err == nil {
		t.Fatal("expected conflicting transports to fail")
	}
}

func TestParseArgsFailsClosedForHTTPOnlyWithoutAuth(t *testing.T) {
	if _, err := ParseArgs([]string{"--http-only"}, envMap(nil)); err == nil {
		t.Fatal("expected unauthenticated HTTP-only mode to fail")
	}
	if _, err := ParseArgs([]string{"--http-only", "--allow-unauthenticated-http"}, envMap(nil)); err != nil {
		t.Fatalf("explicit unauthenticated opt-out should be accepted: %v", err)
	}
}

func TestParseArgsReadsAuthTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(" file-secret \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseArgs([]string{"--http-only", "--auth-token-file", path}, envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthToken != "file-secret" {
		t.Fatalf("auth token = %q", cfg.AuthToken)
	}
}
