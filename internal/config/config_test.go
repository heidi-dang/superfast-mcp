package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestCurrentVersion(t *testing.T) {
	cfg, err := ParseArgs([]string{"--allow-unauthenticated-http"}, envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != "0.3.0" {
		t.Fatalf("version=%q, want 0.3.0", cfg.Version)
	}
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

func TestParseArgsReadsNativeOAuthConfiguration(t *testing.T) {
	cfg, err := ParseArgs([]string{"--http-only"}, envMap(map[string]string{
		"SUPERFAST_PUBLIC_URL":              "https://superfast.example.com",
		"SUPERFAST_CF_ACCESS_ISSUER":        "https://team.cloudflareaccess.com",
		"SUPERFAST_CF_ACCESS_AUDIENCE":      "app-aud",
		"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL": "owner@example.com",
		"SUPERFAST_NATIVE_OAUTH_SECRET":     strings.Repeat("s", 32),
		"SUPERFAST_NATIVE_OAUTH_DB":         "/var/lib/superfast-mcp/oauth/state.db",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NativeOAuth == nil {
		t.Fatal("missing native OAuth config")
	}
	if cfg.NativeOAuth.Issuer != "https://superfast.example.com" {
		t.Fatalf("Issuer=%q", cfg.NativeOAuth.Issuer)
	}
	if cfg.NativeOAuth.Resource != "https://superfast.example.com/mcp" {
		t.Fatalf("Resource=%q", cfg.NativeOAuth.Resource)
	}
	if !slices.Equal(cfg.NativeOAuth.Scopes, []string{"mcp"}) {
		t.Fatalf("Scopes=%v", cfg.NativeOAuth.Scopes)
	}
	if cfg.NativeOAuth.Secret != strings.Repeat("s", 32) {
		t.Fatal("native OAuth secret was not preserved")
	}
	if cfg.NativeOAuth.StateDB != "/var/lib/superfast-mcp/oauth/state.db" {
		t.Fatalf("StateDB=%q", cfg.NativeOAuth.StateDB)
	}
	if cfg.NativeOAuth.AdvertiseNativeMetadata {
		t.Fatal("AdvertiseNativeMetadata=true, want false by default")
	}
}

func TestParseArgsReadsNativeOAuthMetadataAdvertisementFlag(t *testing.T) {
	cfg, err := ParseArgs([]string{"--http-only"}, envMap(map[string]string{
		"SUPERFAST_PUBLIC_URL":                 "https://superfast.example.com",
		"SUPERFAST_CF_ACCESS_ISSUER":           "https://team.cloudflareaccess.com",
		"SUPERFAST_CF_ACCESS_AUDIENCE":         "app-aud",
		"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL":    "owner@example.com",
		"SUPERFAST_NATIVE_OAUTH_SECRET":        strings.Repeat("s", 32),
		"SUPERFAST_NATIVE_OAUTH_DB":            "/var/lib/superfast-mcp/oauth/state.db",
		"SUPERFAST_NATIVE_OAUTH_ADVERTISE":     "true",
		"SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP": "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NativeOAuth == nil || !cfg.NativeOAuth.AdvertiseNativeMetadata {
		t.Fatalf("AdvertiseNativeMetadata=%v, want true", cfg.NativeOAuth != nil && cfg.NativeOAuth.AdvertiseNativeMetadata)
	}
}

func TestParseArgsRejectsNativeOAuthWithoutCloudflareLoginIdentity(t *testing.T) {
	_, err := ParseArgs([]string{"--http-only"}, envMap(map[string]string{
		"SUPERFAST_AUTH_TOKEN":          "break-glass",
		"SUPERFAST_PUBLIC_URL":          "https://superfast.example.com",
		"SUPERFAST_NATIVE_OAUTH_SECRET": strings.Repeat("s", 32),
		"SUPERFAST_NATIVE_OAUTH_DB":     "/var/lib/superfast-mcp/oauth/state.db",
	}))
	if err == nil || !strings.Contains(err.Error(), "Cloudflare Access") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseArgsRejectsWeakOrPartialNativeOAuthConfiguration(t *testing.T) {
	base := map[string]string{
		"SUPERFAST_AUTH_TOKEN":              "break-glass",
		"SUPERFAST_PUBLIC_URL":              "https://superfast.example.com",
		"SUPERFAST_CF_ACCESS_ISSUER":        "https://team.cloudflareaccess.com",
		"SUPERFAST_CF_ACCESS_AUDIENCE":      "app-aud",
		"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL": "owner@example.com",
	}
	cases := []map[string]string{
		{"SUPERFAST_NATIVE_OAUTH_SECRET": "short", "SUPERFAST_NATIVE_OAUTH_DB": "/var/lib/superfast-mcp/oauth/state.db"},
		{"SUPERFAST_NATIVE_OAUTH_SECRET": strings.Repeat("s", 32)},
		{"SUPERFAST_NATIVE_OAUTH_DB": "/var/lib/superfast-mcp/oauth/state.db"},
		{"SUPERFAST_NATIVE_OAUTH_SECRET": strings.Repeat("s", 32), "SUPERFAST_NATIVE_OAUTH_DB": "/var/lib/superfast-mcp/oauth/state.db", "SUPERFAST_NATIVE_OAUTH_ISSUER": "http://bad.example.com"},
	}
	for i, extra := range cases {
		env := make(map[string]string, len(base)+len(extra))
		for k, v := range base {
			env[k] = v
		}
		for k, v := range extra {
			env[k] = v
		}
		if _, err := ParseArgs([]string{"--http-only"}, envMap(env)); err == nil {
			t.Fatalf("case %d: expected native OAuth config rejection", i)
		}
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

func TestParseArgsCloudflareAccessNilWhenUnset(t *testing.T) {
	cfg, err := ParseArgs([]string{"--allow-unauthenticated-http"}, envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CloudflareAccess != nil {
		t.Fatalf("CloudflareAccess = %#v, want nil", cfg.CloudflareAccess)
	}
}

func TestParseArgsCloudflareAccessComplete(t *testing.T) {
	cfg, err := ParseArgs(nil, envMap(map[string]string{
		"SUPERFAST_PUBLIC_URL":                 "https://mcp.example.com/",
		"SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP": "true",
		"SUPERFAST_CF_ACCESS_ISSUER":           "https://team.cloudflareaccess.com/",
		"SUPERFAST_CF_ACCESS_AUDIENCE":         "test-aud",
		"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL":    "admin@example.com",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CloudflareAccess == nil {
		t.Fatal("expected CloudflareAccess to be configured, got nil")
	}
	if cfg.CloudflareAccess.Issuer != "https://team.cloudflareaccess.com" {
		t.Fatalf("Issuer = %q, want normalized without trailing slash", cfg.CloudflareAccess.Issuer)
	}
	if cfg.CloudflareAccess.Audience != "test-aud" {
		t.Fatalf("Audience = %q, want test-aud", cfg.CloudflareAccess.Audience)
	}
	if cfg.CloudflareAccess.AllowedEmail != "admin@example.com" {
		t.Fatalf("AllowedEmail = %q, want admin@example.com", cfg.CloudflareAccess.AllowedEmail)
	}
	if cfg.CloudflareAccess.JWKSURL != "https://team.cloudflareaccess.com/cdn-cgi/access/certs" {
		t.Fatalf("JWKSURL = %q, want defaulted certs URL", cfg.CloudflareAccess.JWKSURL)
	}
	if cfg.CloudflareAccess.Resource != "https://mcp.example.com/mcp" {
		t.Fatalf("Resource = %q, want https://mcp.example.com/mcp", cfg.CloudflareAccess.Resource)
	}
	if len(cfg.CloudflareAccess.RequiredScopes) != 0 {
		t.Fatalf("RequiredScopes = %#v, want no default scope requirement for standard Cloudflare Access JWTs", cfg.CloudflareAccess.RequiredScopes)
	}
}

func TestParseArgsCloudflareAccessCustomJWKSAndScopes(t *testing.T) {
	cfg, err := ParseArgs(nil, envMap(map[string]string{
		"SUPERFAST_PUBLIC_URL":                 "https://mcp.example.com",
		"SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP": "true",
		"SUPERFAST_CF_ACCESS_ISSUER":           "https://team.cloudflareaccess.com",
		"SUPERFAST_CF_ACCESS_AUDIENCE":         "test-aud",
		"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL":    "admin@example.com",
		"SUPERFAST_CF_ACCESS_JWKS_URL":         "https://custom.example.com/certs",
		"SUPERFAST_CF_ACCESS_REQUIRED_SCOPES":  "mcp, read, write",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CloudflareAccess == nil {
		t.Fatal("expected CloudflareAccess to be configured")
	}
	if cfg.CloudflareAccess.JWKSURL != "https://custom.example.com/certs" {
		t.Fatalf("JWKSURL = %q, want custom JWKS URL", cfg.CloudflareAccess.JWKSURL)
	}
	wantScopes := []string{"mcp", "read", "write"}
	if len(cfg.CloudflareAccess.RequiredScopes) != len(wantScopes) {
		t.Fatalf("RequiredScopes = %#v, want %#v", cfg.CloudflareAccess.RequiredScopes, wantScopes)
	}
	for i, s := range wantScopes {
		if cfg.CloudflareAccess.RequiredScopes[i] != s {
			t.Fatalf("RequiredScopes[%d] = %q, want %q", i, cfg.CloudflareAccess.RequiredScopes[i], s)
		}
	}
}

func TestParseArgsCloudflareAccessPartialRejection(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "only issuer",
			env: map[string]string{
				"SUPERFAST_CF_ACCESS_ISSUER": "https://team.cloudflareaccess.com",
			},
		},
		{
			name: "only audience",
			env: map[string]string{
				"SUPERFAST_CF_ACCESS_AUDIENCE": "test-aud",
			},
		},
		{
			name: "only allowed email",
			env: map[string]string{
				"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL": "admin@example.com",
			},
		},
		{
			name: "only JWKS URL",
			env: map[string]string{
				"SUPERFAST_CF_ACCESS_JWKS_URL": "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
			},
		},
		{
			name: "only required scopes",
			env: map[string]string{
				"SUPERFAST_CF_ACCESS_REQUIRED_SCOPES": "mcp",
			},
		},
		{
			name: "missing public url",
			env: map[string]string{
				"SUPERFAST_CF_ACCESS_ISSUER":        "https://team.cloudflareaccess.com",
				"SUPERFAST_CF_ACCESS_AUDIENCE":      "test-aud",
				"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL": "admin@example.com",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseArgs([]string{"--allow-unauthenticated-http"}, envMap(tc.env))
			if err == nil {
				t.Fatalf("expected error for partial config %s, got nil", tc.name)
			}
		})
	}
}

func TestParseArgsCloudflareAccessURLValidation(t *testing.T) {
	validEnv := func() map[string]string {
		return map[string]string{
			"SUPERFAST_PUBLIC_URL":                 "https://mcp.example.com",
			"SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP": "true",
			"SUPERFAST_CF_ACCESS_ISSUER":           "https://team.cloudflareaccess.com",
			"SUPERFAST_CF_ACCESS_AUDIENCE":         "test-aud",
			"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL":    "admin@example.com",
		}
	}

	badURLs := []struct {
		name string
		key  string
		val  string
	}{
		{name: "issuer non-https", key: "SUPERFAST_CF_ACCESS_ISSUER", val: "http://team.cloudflareaccess.com"},
		{name: "issuer relative", key: "SUPERFAST_CF_ACCESS_ISSUER", val: "/team"},
		{name: "issuer missing host", key: "SUPERFAST_CF_ACCESS_ISSUER", val: "https://"},
		{name: "jwks non-https", key: "SUPERFAST_CF_ACCESS_JWKS_URL", val: "http://team.cloudflareaccess.com/certs"},
		{name: "jwks relative", key: "SUPERFAST_CF_ACCESS_JWKS_URL", val: "/certs"},
	}

	for _, tc := range badURLs {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnv()
			env[tc.key] = tc.val
			_, err := ParseArgs(nil, envMap(env))
			if err == nil {
				t.Fatalf("expected error for %s (%s=%q), got nil", tc.name, tc.key, tc.val)
			}
		})
	}
}

func TestParseArgsCloudflareAccessRejectsEmptyScopes(t *testing.T) {
	validEnv := func() map[string]string {
		return map[string]string{
			"SUPERFAST_PUBLIC_URL":                 "https://mcp.example.com",
			"SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP": "true",
			"SUPERFAST_CF_ACCESS_ISSUER":           "https://team.cloudflareaccess.com",
			"SUPERFAST_CF_ACCESS_AUDIENCE":         "test-aud",
			"SUPERFAST_CF_ACCESS_ALLOWED_EMAIL":    "admin@example.com",
		}
	}

	badScopes := []string{
		"mcp,",
		",mcp",
		"mcp, ,read",
		",",
		"   ",
	}

	for _, s := range badScopes {
		t.Run("scope="+s, func(t *testing.T) {
			env := validEnv()
			env["SUPERFAST_CF_ACCESS_REQUIRED_SCOPES"] = s
			_, err := ParseArgs(nil, envMap(env))
			if err == nil {
				t.Fatalf("expected error for empty scope in %q, got nil", s)
			}
		})
	}
}
