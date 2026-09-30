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

func registerAuthRoutes(mux *http.ServeMux, cfg *config.Config) {
	svc := cfg.IAM
	as := newAuthService(cfg)

	flow := newChain(svc.CSRFGuard)
	mux.Handle("POST /passkey/login/begin", flow.thenFunc(svc.Passkey.BeginLogin))
	mux.Handle("POST /passkey/login/finish", flow.thenFunc(svc.Passkey.FinishLogin))
	mux.Handle("POST /passkey/signup/begin", flow.thenFunc(svc.Passkey.BeginSignup))
	mux.Handle("POST /passkey/signup/finish", flow.thenFunc(svc.Passkey.FinishSignup))

	// BeginRegistration checks the principal itself, so no RequireLogin.
	addKey := newChain(svc.Middleware, svc.CSRFGuard)
	mux.Handle("POST /passkey/register/begin", addKey.thenFunc(svc.Passkey.BeginRegistration))
	mux.Handle("POST /passkey/register/finish", addKey.thenFunc(svc.Passkey.FinishRegistration))

	// CLI device endpoints are public (RFC 8628), approval needs a session.
	mux.HandleFunc("POST /auth/device", svc.Device.Begin)
	mux.HandleFunc("POST /auth/device/token", svc.Device.Poll)
	mux.HandleFunc("GET /auth/device/nonce", svc.Device.Nonce)

	deviceGuard := newChain(svc.Middleware, svc.RequireLogin)
	mux.Handle("POST /auth/device/verify", deviceGuard.thenFunc(svc.Device.Verify))
	mux.Handle("POST /auth/device/deny", deviceGuard.thenFunc(svc.Device.Deny))

	// Give passkey logins and signups the same side effects as password ones.
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

	// Optional auth on login lets a signed-in user link a provider.
	// Callbacks are public, the SAML ACS is a cross-origin IdP form post.
	optAuth := newChain(svc.Middleware, svc.CSRFGuard)
	mux.Handle("GET /oidc/login", optAuth.thenFunc(svc.OIDC.Login))
	mux.Handle("POST /oidc/callback", http.HandlerFunc(svc.OIDC.Callback))
	mux.Handle("GET /oidc/callback", http.HandlerFunc(svc.OIDC.Callback))
	mux.Handle("GET /oauth/login", optAuth.thenFunc(svc.OAuth2.Login))
	mux.Handle("POST /oauth/callback", http.HandlerFunc(svc.OAuth2.Callback))
	mux.Handle("GET /oauth/callback", http.HandlerFunc(svc.OAuth2.Callback))
	mux.Handle("GET /saml/login", optAuth.thenFunc(svc.SAML.Login))
	mux.Handle("POST /saml/acs", http.HandlerFunc(svc.SAML.Callback))
	mux.Handle("GET /saml/metadata", http.HandlerFunc(svc.SAML.Metadata))
	mux.Handle("GET /saml/metadata/{id}", http.HandlerFunc(svc.SAML.Metadata))
	mux.Handle("GET /saml/certificate", http.HandlerFunc(svc.SAML.Certificate))
	mux.Handle("GET /saml/certificate/{id}", http.HandlerFunc(svc.SAML.Certificate))

	// SCIM has no session or CSRF, the workspace-scoped token is the only gate.
	if cfg.IAM.SCIM != nil {
		mux.Handle("/scim/v2/{workspace_id}", cfg.IAM.SCIMHandler())
		mux.Handle("/scim/v2/{workspace_id}/", cfg.IAM.SCIMHandler())
	}
}
