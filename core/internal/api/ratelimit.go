package api

import (
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/go-chi/httprate"

	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/realip"
)

// Per client IP, sized for an office behind one IP. DDoS is the proxy's job.
const (
	generalPerMinute = 6000

	// Spraying and enumeration surface, sign-in mails also have a cooldown.
	authPerMinute = 300

	// Anyone can start a device login. This caps the grants one IP can park.
	deviceStartsPerWindow = 30
	deviceStartWindow     = 15 * time.Minute

	// A signup makes a workspace and a mail. One person needs a few tries.
	signupsPerWindow = 10
	signupWindow     = time.Hour
)

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	general := httprate.LimitBy(generalPerMinute, time.Minute, clientIP)(next)
	auth := httprate.LimitBy(authPerMinute, time.Minute, clientIP)(next)
	deviceStart := httprate.LimitBy(deviceStartsPerWindow, deviceStartWindow, clientIP)(next)
	// An RPC error, the signup form reads a bare 429 as the server gone.
	rpcErrors := connecthttp.NewErrorWriter()
	signup := httprate.LimitBy(signupsPerWindow, signupWindow, clientIP,
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			_ = rpcErrors.Write(w, r, connect.NewError(
				connect.CodeResourceExhausted, "too many signups from this network, try again later",
			))
		}),
	)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !rateLimited(r.URL.Path):
			next.ServeHTTP(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/auth/device":
			deviceStart.ServeHTTP(w, r)
		case r.URL.Path == nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure:
			signup.ServeHTTP(w, r)
		case isAuthRoute(r.URL.Path):
			auth.ServeHTTP(w, r)
		default:
			general.ServeHTTP(w, r)
		}
	})
}

func clientIP(r *http.Request) (string, error) {
	return realip.Bucket(r.Header, r.RemoteAddr), nil
}

// Enrolling a daemon takes only a token, so it is guessed at like a sign-in.
func isAuthRoute(path string) bool {
	return path == nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure ||
		strings.HasPrefix(path, "/nokku.v1.AuthService/") ||
		strings.HasPrefix(path, "/nokku.v1.InvitationService/") ||
		strings.HasPrefix(path, "/auth/") ||
		strings.HasPrefix(path, "/oidc/") ||
		strings.HasPrefix(path, "/passkey/")
}

// A limit would block daemon reconnect storms. Hashed assets are left out too.
func rateLimited(path string) bool {
	return path != nokkuv1connect.DaemonControlServiceConnectProcedure &&
		path != nokkuv1connect.DaemonControlServiceDaemonRelayProcedure &&
		!strings.HasPrefix(path, "/_app/")
}
