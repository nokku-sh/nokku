package api

import (
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/go-chi/httprate"

	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/realip"
)

// Limits count per client IP and minute, sized for an office behind one address. A real DDoS is the proxy's job.
const (
	generalPerMinute = 6000

	// Auth endpoints are the spraying and enumeration surface. Sign-in mails also wait out a cooldown per address.
	authPerMinute = 300

	// Anyone can start a device login and it parks a grant until it expires. This is how many one address can hold.
	deviceStartsPerWindow = 30
	deviceStartWindow     = 15 * time.Minute

	// A hosted signup makes a workspace and a mail. A person needs one, plus a few tries until a name is free.
	signupsPerWindow = 10
	signupWindow     = time.Hour
)

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	general := httprate.LimitBy(generalPerMinute, time.Minute, clientIP)(next)
	auth := httprate.LimitBy(authPerMinute, time.Minute, clientIP)(next)
	deviceStart := httprate.LimitBy(deviceStartsPerWindow, deviceStartWindow, clientIP)(next)
	// Answered as an RPC error, the signup form reads a bare 429 as the server being gone.
	rpcErrors := connect.NewErrorWriter()
	signup := httprate.LimitBy(signupsPerWindow, signupWindow, clientIP,
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			_ = rpcErrors.Write(w, r, newError(
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

// Enrolling a daemon is open to anyone with a token, so it is guessed at like a sign-in.
func isAuthRoute(path string) bool {
	return path == nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure ||
		strings.HasPrefix(path, "/nokku.v1.AuthService/") ||
		strings.HasPrefix(path, "/nokku.v1.InvitationService/") ||
		strings.HasPrefix(path, "/auth/") ||
		strings.HasPrefix(path, "/oidc/") ||
		strings.HasPrefix(path, "/passkey/")
}

// rateLimited leaves out the daemon streams, where a limit would block reconnect storms, and the hashed assets.
func rateLimited(path string) bool {
	return path != nokkuv1connect.DaemonControlServiceConnectProcedure &&
		path != nokkuv1connect.DaemonControlServiceDaemonRelayProcedure &&
		!strings.HasPrefix(path, "/_app/")
}
