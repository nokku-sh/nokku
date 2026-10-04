package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/httprate"

	"github.com/nokku-sh/nokku/internal/util"
)

// Limits count per client IP and minute. A whole office can sit behind one
// address, or behind a proxy nobody listed in NOKKU_TRUSTED_PROXIES, so they
// are sized for a few hundred people sharing it. They stop one source from
// flooding the server. A real DDoS is the reverse proxy's job.
const (
	generalPerMinute = 6000

	// Auth endpoints are the spraying and enumeration surface. Guessing one
	// account's password is capped per account in iam.
	authPerMinute = 300
)

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	general := httprate.LimitBy(generalPerMinute, time.Minute, clientIP)(next)
	auth := httprate.LimitBy(authPerMinute, time.Minute, clientIP)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !rateLimited(r.URL.Path):
			next.ServeHTTP(w, r)
		case isAuthRoute(r.URL.Path):
			auth.ServeHTTP(w, r)
		default:
			general.ServeHTTP(w, r)
		}
	})
}

func clientIP(r *http.Request) (string, error) {
	return util.GetRemoteIP(r.Header, r.RemoteAddr), nil
}

func isAuthRoute(path string) bool {
	return strings.HasPrefix(path, "/nokku.v1.AuthService/") ||
		strings.HasPrefix(path, "/auth/") ||
		strings.HasPrefix(path, "/oidc/") ||
		strings.HasPrefix(path, "/oauth/") ||
		strings.HasPrefix(path, "/saml/") ||
		strings.HasPrefix(path, "/passkey/")
}

// rateLimited leaves out only the daemon streams, where a limit would block
// legitimate reconnect storms, and the hashed static assets.
func rateLimited(path string) bool {
	return !strings.HasPrefix(path, "/nokku.v1.DaemonControlService/") &&
		!strings.HasPrefix(path, "/nokku.v1.DaemonSessionService/") &&
		!strings.HasPrefix(path, "/_app/")
}
