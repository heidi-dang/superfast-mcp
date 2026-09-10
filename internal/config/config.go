package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type CloudflareAccessConfig struct {
	Issuer         string
	Audience       string
	AllowedEmail   string
	JWKSURL        string
	Resource       string
	RequiredScopes []string
}

type NativeOAuthConfig struct {
	Issuer   string
	Resource string
	Scopes   []string
	Secret   string
	StateDB  string
}

type Config struct {
	HTTPAddr                 string
	PublicURL                string
	Roots                    []string
	StdioOnly                bool
	HTTPOnly                 bool
	LogJSON                  bool
	AuthToken                string
	OAuthOwnerPassword       string
	AllowUnauthenticatedHTTP bool
	Version                  string
	CloudflareAccess         *CloudflareAccessConfig
	NativeOAuth              *NativeOAuthConfig
}

func Parse() (*Config, error) {
	return ParseArgs(os.Args[1:], os.Getenv)
}

func ParseArgs(args []string, getenv func(string) string) (*Config, error) {
	stdioOnly, err := envBool(getenv, "SUPERFAST_STDIO_ONLY")
	if err != nil {
		return nil, err
	}
	httpOnly, err := envBool(getenv, "SUPERFAST_HTTP_ONLY")
	if err != nil {
		return nil, err
	}
	logJSON, err := envBool(getenv, "SUPERFAST_LOG_JSON")
	if err != nil {
		return nil, err
	}
	allowUnauthenticated, err := envBool(getenv, "SUPERFAST_ALLOW_UNAUTHENTICATED_HTTP")
	if err != nil {
		return nil, err
	}

	c := &Config{
		HTTPAddr:                 envDefault(getenv, "SUPERFAST_HTTP", "127.0.0.1:8787"),
		PublicURL:                strings.TrimRight(getenv("SUPERFAST_PUBLIC_URL"), "/"),
		StdioOnly:                stdioOnly,
		HTTPOnly:                 httpOnly,
		LogJSON:                  logJSON,
		AuthToken:                strings.TrimSpace(getenv("SUPERFAST_AUTH_TOKEN")),
		OAuthOwnerPassword:       strings.TrimSpace(getenv("SUPERFAST_OAUTH_OWNER_PASSWORD")),
		AllowUnauthenticatedHTTP: allowUnauthenticated,
		Version:                  "0.3.0",
	}
	rootsValue := getenv("SUPERFAST_ROOTS")
	authTokenFile := strings.TrimSpace(getenv("SUPERFAST_AUTH_TOKEN_FILE"))

	flags := flag.NewFlagSet("superfast-mcp", flag.ContinueOnError)
	flags.StringVar(&c.HTTPAddr, "http", c.HTTPAddr, "HTTP listen address for Streamable HTTP (empty to disable)")
	flags.StringVar(&c.PublicURL, "public-url", c.PublicURL, "Public base URL (e.g. https://mcp.example.com)")
	flags.StringVar(&rootsValue, "roots", rootsValue, "Comma-separated workspace roots")
	flags.StringVar(&authTokenFile, "auth-token-file", authTokenFile, "Read HTTP bearer token from file")
	flags.BoolVar(&c.StdioOnly, "stdio-only", c.StdioOnly, "Run only stdio transport")
	flags.BoolVar(&c.HTTPOnly, "http-only", c.HTTPOnly, "Run only HTTP transport")
	flags.BoolVar(&c.LogJSON, "log-json", c.LogJSON, "Emit JSON structured logs")
	flags.BoolVar(&c.AllowUnauthenticatedHTTP, "allow-unauthenticated-http", c.AllowUnauthenticatedHTTP, "Explicitly allow HTTP MCP without bearer authentication")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if c.StdioOnly && c.HTTPOnly {
		return nil, fmt.Errorf("--stdio-only and --http-only are mutually exclusive")
	}
	if c.HTTPOnly && strings.TrimSpace(c.HTTPAddr) == "" {
		return nil, fmt.Errorf("--http-only requires a non-empty --http address")
	}

	if authTokenFile != "" {
		data, err := os.ReadFile(authTokenFile)
		if err != nil {
			return nil, fmt.Errorf("read auth token file: %w", err)
		}
		c.AuthToken = strings.TrimSpace(string(data))
	}
	for _, root := range strings.Split(rootsValue, ",") {
		root = strings.TrimSpace(root)
		if root != "" {
			c.Roots = append(c.Roots, root)
		}
	}
	if len(c.Roots) == 0 {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("determine working directory: %w", err)
		}
		c.Roots = []string{wd}
	}
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")

	rawIssuer := getenv("SUPERFAST_CF_ACCESS_ISSUER")
	rawAudience := getenv("SUPERFAST_CF_ACCESS_AUDIENCE")
	rawAllowedEmail := getenv("SUPERFAST_CF_ACCESS_ALLOWED_EMAIL")
	rawJWKSURL := getenv("SUPERFAST_CF_ACCESS_JWKS_URL")
	rawRequiredScopes := getenv("SUPERFAST_CF_ACCESS_REQUIRED_SCOPES")

	if rawIssuer != "" || rawAudience != "" || rawAllowedEmail != "" || rawJWKSURL != "" || rawRequiredScopes != "" {
		issuer := strings.TrimSpace(rawIssuer)
		if issuer == "" {
			return nil, fmt.Errorf("missing Cloudflare Access issuer")
		}
		audience := strings.TrimSpace(rawAudience)
		if audience == "" {
			return nil, fmt.Errorf("missing Cloudflare Access audience")
		}
		allowedEmail := strings.TrimSpace(rawAllowedEmail)
		if allowedEmail == "" {
			return nil, fmt.Errorf("missing Cloudflare Access allowed email")
		}
		if c.PublicURL == "" {
			return nil, fmt.Errorf("missing SUPERFAST_PUBLIC_URL required by Cloudflare Access")
		}

		issuer = strings.TrimSuffix(issuer, "/")
		if err := validateAbsoluteHTTPS(issuer, "Cloudflare Access issuer"); err != nil {
			return nil, err
		}

		jwksURL := strings.TrimSpace(rawJWKSURL)
		if jwksURL == "" {
			jwksURL = issuer + "/cdn-cgi/access/certs"
		}
		if err := validateAbsoluteHTTPS(jwksURL, "Cloudflare Access JWKS URL"); err != nil {
			return nil, err
		}

		resource := c.PublicURL + "/mcp"

		var requiredScopes []string
		if rawRequiredScopes != "" {
			if strings.TrimSpace(rawRequiredScopes) == "" {
				return nil, fmt.Errorf("invalid Cloudflare Access required scopes: empty entries are not allowed")
			}
			for _, part := range strings.Split(rawRequiredScopes, ",") {
				scope := strings.TrimSpace(part)
				if scope == "" {
					return nil, fmt.Errorf("invalid Cloudflare Access required scopes: empty entries are not allowed")
				}
				requiredScopes = append(requiredScopes, scope)
			}
		}

		c.CloudflareAccess = &CloudflareAccessConfig{
			Issuer:         issuer,
			Audience:       audience,
			AllowedEmail:   allowedEmail,
			JWKSURL:        jwksURL,
			Resource:       resource,
			RequiredScopes: requiredScopes,
		}
	}

	rawNativeIssuer := getenv("SUPERFAST_NATIVE_OAUTH_ISSUER")
	rawNativeResource := getenv("SUPERFAST_NATIVE_OAUTH_RESOURCE")
	rawNativeScopes := getenv("SUPERFAST_NATIVE_OAUTH_SCOPES")
	rawNativeSecret := getenv("SUPERFAST_NATIVE_OAUTH_SECRET")
	rawNativeDB := getenv("SUPERFAST_NATIVE_OAUTH_DB")
	if rawNativeIssuer != "" || rawNativeResource != "" || rawNativeScopes != "" || rawNativeSecret != "" || rawNativeDB != "" {
		if c.PublicURL == "" {
			return nil, fmt.Errorf("missing SUPERFAST_PUBLIC_URL required by native OAuth")
		}
		if c.CloudflareAccess == nil {
			return nil, fmt.Errorf("native OAuth requires complete Cloudflare Access configuration for /oauth/login")
		}
		secret := strings.TrimSpace(rawNativeSecret)
		if len(secret) < 32 {
			return nil, fmt.Errorf("native OAuth secret must be at least 32 characters")
		}
		stateDB := strings.TrimSpace(rawNativeDB)
		if stateDB == "" {
			return nil, fmt.Errorf("native OAuth state database path is required")
		}
		issuer := strings.TrimRight(strings.TrimSpace(rawNativeIssuer), "/")
		if issuer == "" {
			issuer = c.PublicURL
		}
		if err := validateAbsoluteHTTPS(issuer, "native OAuth issuer"); err != nil {
			return nil, err
		}
		resource := strings.TrimSpace(rawNativeResource)
		if resource == "" {
			resource = c.PublicURL + "/mcp"
		}
		if err := validateAbsoluteHTTPS(resource, "native OAuth resource"); err != nil {
			return nil, err
		}
		scopes, err := parseScopeList(rawNativeScopes)
		if err != nil {
			return nil, fmt.Errorf("invalid native OAuth scopes: %w", err)
		}
		if len(scopes) == 0 {
			scopes = []string{"mcp"}
		}
		c.NativeOAuth = &NativeOAuthConfig{
			Issuer:   issuer,
			Resource: resource,
			Scopes:   scopes,
			Secret:   secret,
			StateDB:  stateDB,
		}
	}

	if c.AuthToken == "" && c.CloudflareAccess == nil && c.NativeOAuth == nil && !c.AllowUnauthenticatedHTTP && c.HTTPOnly {
		return nil, fmt.Errorf("HTTP mode requires static bearer, Cloudflare Access, or native OAuth authentication; use --allow-unauthenticated-http only for intentionally unprotected deployments")
	}

	return c, nil
}

func parseScopeList(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	seen := make(map[string]struct{})
	var scopes []string
	for _, commaPart := range strings.Split(raw, ",") {
		commaPart = strings.TrimSpace(commaPart)
		if commaPart == "" {
			return nil, fmt.Errorf("empty scope entry")
		}
		for _, scope := range strings.Fields(commaPart) {
			if _, ok := seen[scope]; ok {
				continue
			}
			seen[scope] = struct{}{}
			scopes = append(scopes, scope)
		}
	}
	return scopes, nil
}

func validateAbsoluteHTTPS(rawURL, fieldName string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s must be a valid URL: %w", fieldName, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute HTTPS URL: %s", fieldName, rawURL)
	}
	return nil
}

func envDefault(getenv func(string) string, key, fallback string) string {
	if value := strings.TrimSpace(getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(getenv func(string) string, key string) (bool, error) {
	value := strings.TrimSpace(getenv(key))
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}
