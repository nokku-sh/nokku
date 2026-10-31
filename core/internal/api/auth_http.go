package api

import (
	"net/http"

	"github.com/nokku-sh/nokku/core/internal/config"
)

// maxAuthBody fits any WebAuthn answer and form these routes take, they are public.
const maxAuthBody = 64 << 10

func registerAuthRoutes(mux *http.ServeMux, cfg *config.Config) {
	svc := cfg.IAM
	limit := func(h http.Handler) http.Handler { return http.MaxBytesHandler(h, maxAuthBody) }
	public := chain(limit)
	session := chain(limit, svc.Middleware)
	signedIn := chain(limit, svc.Middleware, svc.RequireLogin)
	// Every route that adds a way in takes only a session from the last 10 minutes.
	fresh := chain(limit, svc.Middleware, svc.RequireLogin, svc.RequireFresh)

	// Cross-origin posts are rejected for every route by the server's withCSRF.
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

	// SCIM has no session or CSRF, the workspace-scoped token is the only gate.
	mux.Handle("/scim/v2", cfg.IAM.SCIMHandler())
	mux.Handle("/scim/v2/", cfg.IAM.SCIMHandler())
}
