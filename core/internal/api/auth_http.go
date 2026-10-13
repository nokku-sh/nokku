package api

import (
	"net/http"

	"github.com/nokku-sh/nokku/core/internal/config"
)

func registerAuthRoutes(mux *http.ServeMux, cfg *config.Config) {
	svc := cfg.IAM

	// Cross-origin posts are rejected for every route by the server's withCSRF.
	mux.HandleFunc("POST /passkey/login/begin", svc.Passkey.BeginLogin)
	mux.HandleFunc("POST /passkey/login/finish", svc.Passkey.FinishLogin)

	// BeginRegistration checks the principal itself, so no RequireLogin.
	optAuth := chain(svc.Middleware)
	mux.Handle("POST /passkey/register/begin", optAuth(svc.Passkey.BeginRegistration))
	mux.Handle("POST /passkey/register/finish", optAuth(svc.Passkey.FinishRegistration))

	// CLI device endpoints are public (RFC 8628), approval needs a session.
	mux.HandleFunc("POST /auth/device", svc.Device.Begin)
	mux.HandleFunc("POST /auth/device/token", svc.Device.Poll)
	mux.HandleFunc("GET /auth/device/nonce", svc.Device.Nonce)

	deviceGuard := chain(svc.Middleware, svc.RequireLogin)
	mux.Handle("GET /auth/device/info", deviceGuard(svc.Device.Info))
	mux.Handle("POST /auth/device/verify", deviceGuard(svc.Device.Verify))
	mux.Handle("POST /auth/device/deny", deviceGuard(svc.Device.Deny))

	// Optional auth on login lets a signed-in user link a provider.
	mux.Handle("GET /oidc/login", optAuth(svc.OIDC.Login))
	mux.Handle("POST /oidc/callback", http.HandlerFunc(svc.OIDC.Callback))
	mux.Handle("GET /oidc/callback", http.HandlerFunc(svc.OIDC.Callback))

	// SCIM has no session or CSRF, the workspace-scoped token is the only gate.
	mux.Handle("/scim/v2", cfg.IAM.SCIMHandler())
	mux.Handle("/scim/v2/", cfg.IAM.SCIMHandler())
}
