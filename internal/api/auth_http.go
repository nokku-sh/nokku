package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

// registerAuthRoutes mounts the leftover /auth HTTP surface on mux.
func registerAuthRoutes(mux *http.ServeMux, cfg *config.Config) {
	svc := cfg.IAM
	as := NewAuthService(cfg)

	// Public, CSRF-guarded flows.
	flow := newChain(svc.CSRFGuard)
	mux.Handle("POST /passkey/login/begin", flow.ThenFunc(svc.Passkey.BeginLogin))
	mux.Handle("POST /passkey/login/finish", flow.ThenFunc(svc.Passkey.FinishLogin))
	mux.Handle("POST /passkey/signup/begin", flow.ThenFunc(svc.Passkey.BeginSignup))
	mux.Handle("POST /passkey/signup/finish", flow.ThenFunc(svc.Passkey.FinishSignup))

	// WebAuthn add-key needs a session; BeginRegistration checks the
	// principal itself, so only auth middleware and CSRF wrap the route.
	addKey := newChain(svc.Middleware, svc.CSRFGuard)
	mux.Handle("POST /passkey/register/begin", addKey.ThenFunc(svc.Passkey.BeginRegistration))
	mux.Handle("POST /passkey/register/finish", addKey.ThenFunc(svc.Passkey.FinishRegistration))

	// Device flow: the browser page approves under a session; the CLI
	// endpoints are public (RFC 8628).
	mux.HandleFunc("POST /auth/device", svc.Device.Begin)
	mux.HandleFunc("POST /auth/device/token", svc.Device.Poll)
	mux.HandleFunc("GET /auth/device/nonce", svc.Device.Nonce)

	deviceGuard := newChain(svc.Middleware, svc.RequireLogin)
	mux.Handle("POST /auth/device/verify", deviceGuard.ThenFunc(svc.Device.Verify))
	mux.Handle("POST /auth/device/deny", deviceGuard.ThenFunc(svc.Device.Deny))

	// The hooks give passkey logins the same device remembering and
	// new-login alerts as password logins, and passkey signups the same
	// verification email.
	cfg.IAM.OnUserLogin = func(w http.ResponseWriter, r *http.Request, u *db.User, _ iam.Method) {
		if c := cfg.IAM.RememberDevice(r.Context(), r.Header, r.RemoteAddr, u); c != nil {
			http.SetCookie(w, c)
		}
	}
	cfg.IAM.OnNewDeviceLogin = func(ctx context.Context, u *db.User, sess *db.Session, label, ip string) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := cfg.Email.SendNewLoginEmail(
			ctx,
			u.ID,
			u.Email,
			string(sess.TokenHash),
			label,
			ip,
		); err != nil {
			slog.Debug("failed to send new login email", "error", err)
		}
	}
	cfg.IAM.OnPasskeySignup = func(r *http.Request, u *db.User) {
		as.sendTokenEmail(r.Context(), u, iam.TokenVerifyEmail, true)
	}

	// SSO login flows. These are browser-redirect endpoints, so they mount
	// at the root (the paths IdP administrators register and the UI
	// navigates to), not under the /auth JSON API. Login endpoints run
	// behind optional auth so a signed-in user links a provider; callbacks
	// are public (the SAML ACS is a cross-origin IdP form post, exempt from
	// CSRF by design).
	optAuth := newChain(svc.Middleware, svc.CSRFGuard)
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

	// SCIM 2.0 provisioning. Bearer-token surface mounted at the path IdP
	// administrators register as the connector base URL. No session, no
	// CSRF: the workspace-scoped token lookup is the only gate.
	if cfg.IAM.SCIM != nil {
		mux.Handle("/scim/v2/{workspace_id}", cfg.IAM.SCIMHandler())
		mux.Handle("/scim/v2/{workspace_id}/", cfg.IAM.SCIMHandler())
	}
}
