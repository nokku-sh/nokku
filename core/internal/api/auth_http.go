package api

import (
	"net/http"
	"time"

	"github.com/nokku-sh/nokku/core/internal/iam"
)

// maxAuthBody fits any WebAuthn answer or form these public routes take.
const maxAuthBody = 64 << 10

// A slow body would hold the connection open, the server has no read timeout.
const authBodyTimeout = 10 * time.Second

func registerAuthRoutes(mux *http.ServeMux, svc *iam.Service) {
	limit := limitBody(maxAuthBody, authBodyTimeout)
	public := chain(limit)
	session := chain(limit, svc.Middleware)
	signedIn := chain(limit, svc.Middleware, svc.RequireLogin)
	// A route that adds a way in needs a session from the last 10 minutes.
	fresh := chain(limit, svc.Middleware, svc.RequireLogin, svc.RequireFresh)

	// withCSRF rejects cross-origin posts on every route but the OIDC callback.
	mux.Handle("POST /passkey/login/begin", public(svc.Passkey.BeginLogin))
	mux.Handle("POST /passkey/login/finish", public(svc.Passkey.FinishLogin))
	mux.Handle("POST /passkey/register/begin", fresh(svc.Passkey.BeginRegistration))
	// Finishing needs the ceremony the fresh begin started.
	mux.Handle("POST /passkey/register/finish", session(svc.Passkey.FinishRegistration))

	// CLI device endpoints are public (RFC 8628), approval needs a session.
	mux.Handle("POST /auth/device", public(svc.Device.Begin))
	mux.Handle("POST /auth/device/token", public(svc.Device.Poll))
	mux.HandleFunc("GET /auth/device/nonce", svc.Device.Nonce)
	mux.Handle("GET /auth/device/info", signedIn(svc.Device.Info))
	mux.Handle("POST /auth/device/verify", fresh(svc.Device.Verify))
	// A stale session can still turn down a code it did not start.
	mux.Handle("POST /auth/device/deny", signedIn(svc.Device.Deny))

	mux.HandleFunc("GET /oidc/login", svc.OIDC.Login)
	mux.Handle("GET /oidc/link", fresh(svc.OIDC.Link))
	mux.Handle("POST /oidc/callback", public(svc.OIDC.Callback))
	mux.HandleFunc("GET /oidc/callback", svc.OIDC.Callback)

	// SCIM has no session, the workspace-scoped token is the only gate.
	mux.Handle("/scim/v2", svc.SCIMHandler())
	mux.Handle("/scim/v2/", svc.SCIMHandler())
}

// limitBody caps the size of a request body and the time a client has to send it.
// The deadline ends with the body, a slow handler is not cut.
func limitBody(maxBytes int64, timeout time.Duration) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		limited := http.MaxBytesHandler(h, maxBytes)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Without a body the server already watches the connection, a deadline would cancel the request.
			if r.Body != http.NoBody {
				_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(timeout))
			}
			limited.ServeHTTP(w, r)
		})
	}
}
