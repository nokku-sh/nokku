package api

import (
	"net/http"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/iam"
)

// registerAuthRoutes mounts the leftover /auth HTTP surface on mux.
func registerAuthRoutes(mux *http.ServeMux, cfg *config.Config) {
	svc := cfg.IAM
	as := NewAuthService(cfg)

	// Public, CSRF-guarded flows.
	flow := NewChain(svc.CSRFGuard)
	mux.Handle("POST /passkey/login/begin", flow.ThenFunc(svc.Passkey.BeginLogin))
	mux.Handle("POST /passkey/login/finish", flow.ThenFunc(svc.Passkey.FinishLogin))
	mux.Handle("POST /passkey/signup/begin", flow.ThenFunc(svc.Passkey.BeginSignup))
	mux.Handle("POST /passkey/signup/finish", flow.ThenFunc(svc.Passkey.FinishSignup))

	// WebAuthn add-key needs a session; BeginRegistration checks the
	// principal itself, so only auth middleware and CSRF wrap the route.
	addKey := NewChain(svc.Middleware, svc.CSRFGuard)
	mux.Handle("POST /passkey/register/begin", addKey.ThenFunc(svc.Passkey.BeginRegistration))
	mux.Handle("POST /passkey/register/finish", addKey.ThenFunc(svc.Passkey.FinishRegistration))

	// Device flow: the browser page approves under a session; the CLI
	// endpoints are public (RFC 8628).
	mux.HandleFunc("POST /auth/device", svc.Device.Begin)
	mux.HandleFunc("POST /auth/device/token", svc.Device.Poll)
	mux.HandleFunc("GET /auth/device/nonce", svc.Device.Nonce)

	deviceGuard := NewChain(NewHTTPAuth(cfg))
	mux.Handle("POST /auth/device/verify", deviceGuard.ThenFunc(svc.Device.Verify))
	mux.Handle("POST /auth/device/deny", deviceGuard.ThenFunc(svc.Device.Deny))

	// The hook gives passkey logins the same device remembering and
	// new-login alerts as password logins.
	cfg.IAM.OnUserLogin = func(w http.ResponseWriter, r *http.Request, u iam.User, _ iam.Method) {
		if c := as.reconcileDevice(r.Context(), r.Header, r.RemoteAddr, u); c != nil {
			http.SetCookie(w, c)
		}
	}
	cfg.IAM.OnPasskeySignup = func(r *http.Request, u iam.User) {
		as.sendTokenEmail(r.Context(), u, iam.TokenVerifyEmail, true)
	}

	// SSO login flows. These are browser-redirect endpoints, so they mount
	// at the root (the paths IdP administrators register and the UI
	// navigates to), not under the /auth JSON API. Login endpoints run
	// behind optional auth so a signed-in user links a provider; callbacks
	// are public (the SAML ACS is a cross-origin IdP form post, exempt from
	// CSRF by design).
	optAuth := NewChain(svc.Middleware, svc.CSRFGuard)
	mux.Handle("GET /oidc/login", optAuth.ThenFunc(svc.OIDC.Login))
	mux.Handle("POST /oidc/callback", http.HandlerFunc(svc.OIDC.Callback))
	mux.Handle("GET /oidc/callback", http.HandlerFunc(svc.OIDC.Callback))
	mux.Handle("GET /oauth/login", optAuth.ThenFunc(svc.OAuth2.Login))
	mux.Handle("POST /oauth/callback", http.HandlerFunc(svc.OAuth2.Callback))
	mux.Handle("GET /oauth/callback", http.HandlerFunc(svc.OAuth2.Callback))
	mux.Handle("GET /saml/login", optAuth.ThenFunc(svc.SAML.Login))
	mux.Handle("POST /saml/acs", http.HandlerFunc(svc.SAML.Callback))
	mux.Handle("GET /saml/metadata", http.HandlerFunc(svc.SAML.Metadata))
	mux.Handle("GET /saml/metadata/{id}", http.HandlerFunc(svc.SAML.Metadata))
	mux.Handle("GET /saml/certificate", http.HandlerFunc(svc.SAML.Certificate))
	mux.Handle("GET /saml/certificate/{id}", http.HandlerFunc(svc.SAML.Certificate))
}
