package mcpx

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/heidi-dang/superfast-mcp/internal/access"
	oauthserver "github.com/heidi-dang/superfast-mcp/internal/oauth"
)

type mcpAuthOptions struct {
	StaticToken string
	Access      access.Verifier
	NativeOAuth *oauthserver.Server
}

func authenticateMCP(options mcpAuthOptions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion := strings.TrimSpace(r.Header.Get("Cf-Access-Jwt-Assertion"))
		if assertion != "" && options.Access != nil {
			if _, err := options.Access.Verify(r.Context(), assertion); err == nil {
				next.ServeHTTP(w, r)
				return
			}
		}

		bearer, hasBearer := bearerToken(r.Header.Get("Authorization"))
		if hasBearer {
			if options.StaticToken != "" && subtle.ConstantTimeCompare([]byte(bearer), []byte(options.StaticToken)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
			if options.NativeOAuth != nil && options.NativeOAuth.VerifyAccessToken(bearer) {
				next.ServeHTTP(w, r)
				return
			}
		}

		challenge := `Bearer realm="superfast-mcp"`
		if options.NativeOAuth != nil {
			challenge = fmt.Sprintf(`Bearer realm="superfast-mcp", resource_metadata=%q, scope="mcp"`, options.NativeOAuth.ResourceMetadataURL())
		}
		w.Header().Set("WWW-Authenticate", challenge)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func bearerAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return authenticateMCP(mcpAuthOptions{StaticToken: token}, next)
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}
