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

	cfg.IAM.OnUserLogin = func(w http.ResponseWriter, r *http.Request, u *db.User, _ iam.Method) {
		if c := cfg.IAM.RememberDevice(r.Context(), r.Header, r.RemoteAddr, u); c != nil {
			http.SetCookie(w, c)
		}
	}
	cfg.IAM.OnNewDeviceLogin = func(ctx context.Context, u *db.User, sess *db.Session, label, ip string) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := cfg.Email.SendNewLoginEmail(ctx, u.ID, u.Email, string(sess.TokenHash), label, ip); err != nil {
			slog.Warn("new login email not sent", "error", err)
		}
	}
	// Without mail there are no links, the login page then offers passkeys
	// and the workspace's providers only.
	if !cfg.Email.HasSMTP() {
		return
	}
	cfg.IAM.SendMagicLink = func(ctx context.Context, u *db.User, link string, ttl time.Duration) error {
		return cfg.Email.SendMagicLinkEmail(ctx, u.ID, u.Email, link, ttl.String())
	}
	cfg.IAM.SendSignupLink = func(ctx context.Context, email, name, link string, ttl time.Duration) error {
		return cfg.Email.SendSignupLinkEmail(ctx, email, name, cfg.Tenant.Single().Name, link, ttl.String())
	}
}
