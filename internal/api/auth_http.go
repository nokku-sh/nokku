package api

import (
	"net/http"

	"github.com/nokku-sh/nokku/internal/config"
)

func registerAuthRoutes(mux *http.ServeMux, cfg *config.Config) {
	svc := cfg.IAM

	// Cross-origin posts are rejected for every route by the server's withCSRF.
	mux.HandleFunc("POST /passkey/login/begin", svc.Passkey.BeginLogin)
	mux.HandleFunc("POST /passkey/login/finish", svc.Passkey.FinishLogin)
	// Signup takes an invite, see InvitationService for the mailed way in.
	mux.HandleFunc("POST /passkey/signup/begin", svc.Passkey.BeginSignup)
	mux.HandleFunc("POST /passkey/signup/finish", svc.Passkey.FinishSignup)

	// BeginRegistration checks the principal itself, so no RequireLogin.
	optAuth := newChain(svc.Middleware)
	mux.Handle("POST /passkey/register/begin", optAuth.thenFunc(svc.Passkey.BeginRegistration))
	mux.Handle("POST /passkey/register/finish", optAuth.thenFunc(svc.Passkey.FinishRegistration))

	// CLI device endpoints are public (RFC 8628), approval needs a session.
	mux.HandleFunc("POST /auth/device", svc.Device.Begin)
	mux.HandleFunc("POST /auth/device/token", svc.Device.Poll)
	mux.HandleFunc("GET /auth/device/nonce", svc.Device.Nonce)

	deviceGuard := newChain(svc.Middleware, svc.RequireLogin)
	mux.Handle("GET /auth/device/info", deviceGuard.thenFunc(svc.Device.Info))
	mux.Handle("POST /auth/device/verify", deviceGuard.thenFunc(svc.Device.Verify))
	mux.Handle("POST /auth/device/deny", deviceGuard.thenFunc(svc.Device.Deny))

	// Optional auth on login lets a signed-in user link a provider.
	mux.Handle("GET /oidc/login", optAuth.thenFunc(svc.OIDC.Login))
	mux.Handle("POST /oidc/callback", http.HandlerFunc(svc.OIDC.Callback))
	mux.Handle("GET /oidc/callback", http.HandlerFunc(svc.OIDC.Callback))

	// SCIM has no session or CSRF, the workspace-scoped token is the only gate.
	mux.Handle("/scim/v2", cfg.IAM.SCIMHandler())
	mux.Handle("/scim/v2/", cfg.IAM.SCIMHandler())
}
