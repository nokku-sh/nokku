package api

// The browser-facing auth surface backed by internal/iam. Route shapes and
// JSON fields mirror the contract the web UI already consumes (kagi's
// /auth/* surface), so the UI stays untouched. See
// docs/adr/0001-merge-auth-back-into-nokku.md (D2).

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

const (
	maxPasswordLength = 128
	maxNameLength     = 256
	tokenTTL          = 15 * time.Minute
	sessionTTL        = 24 * time.Hour
)

type authAPI struct {
	cfg *config.Config
}

// registerAuthRoutes mounts the /auth/* surface on mux.
func registerAuthRoutes(mux *http.ServeMux, cfg *config.Config) {
	svc := cfg.IAM
	a := &authAPI{cfg: cfg}

	// Public, CSRF-guarded flows.
	flow := NewChain(svc.CSRFGuard)
	mux.Handle("POST /auth/register", flow.ThenFunc(a.register))
	mux.Handle("POST /auth/login", flow.ThenFunc(a.login))
	mux.Handle("POST /auth/login/backup-code", flow.ThenFunc(a.loginBackupCode))
	mux.Handle("POST /auth/logout", flow.ThenFunc(a.logout))
	mux.Handle("POST /auth/forgot-password", flow.ThenFunc(a.forgotPassword))
	mux.Handle("POST /auth/reset-password", flow.ThenFunc(a.resetPassword))
	mux.Handle("POST /auth/verify-email", flow.ThenFunc(a.verifyEmail))
	mux.Handle("POST /auth/resend-verification", flow.ThenFunc(a.resendVerification))
	mux.Handle("GET /auth/sso/discover", flow.ThenFunc(a.ssoDiscover))
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
		a.rememberDevice(w, r, u)
	}
	cfg.IAM.OnPasskeySignup = func(r *http.Request, u iam.User) {
		a.sendTokenEmail(r, u, iam.TokenVerifyEmail, true)
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

// --- Flows ------------------------------------------------------------------

type registerRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *authAPI) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)
	if req.Email == "" || req.Password == "" {
		iam.WriteError(
			w,
			http.StatusBadRequest,
			"missing_fields",
			"email and password are required",
		)
		return
	}
	if len(req.Password) < 8 {
		iam.WriteError(
			w,
			http.StatusBadRequest,
			"password_too_short",
			"password must be at least 8 characters",
		)
		return
	}
	if len(req.Password) > maxPasswordLength {
		iam.WriteError(w, http.StatusBadRequest, "password_too_long", "password is too long")
		return
	}
	if len(req.Name) > maxNameLength {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}

	u, err := a.cfg.IAM.Register(r.Context(), req.Email, req.Name, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrEmailTaken):
			iam.WriteError(
				w,
				http.StatusConflict,
				"email_taken",
				"an account with this email already exists",
			)
		default:
			iam.WriteError(
				w,
				http.StatusInternalServerError,
				"internal_error",
				"something went wrong",
			)
		}
		return
	}

	a.sendTokenEmail(r, u, iam.TokenVerifyEmail, true)
	iam.WriteOK(w)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *authAPI) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	u, err := a.cfg.IAM.Password.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		a.rejectLogin(w, err)
		return
	}
	a.issueSession(w, r, u, iam.MethodPassword)
}

type backupCodeLoginRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (a *authAPI) loginBackupCode(w http.ResponseWriter, r *http.Request) {
	var req backupCodeLoginRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	u, err := a.cfg.IAM.LoginWithBackupCode(r.Context(), req.Email, req.Code)
	if err != nil {
		a.rejectLogin(w, err)
		return
	}
	a.issueSession(w, r, u, iam.MethodBackupCode)
}

// issueSession creates the web session, writes the cookie, and reconciles
// the remembered device (new device => one geo-located security alert).
func (a *authAPI) issueSession(
	w http.ResponseWriter,
	r *http.Request,
	u *db.User,
	method iam.Method,
) {
	sess, token, err := a.cfg.IAM.Sessions.Issue(r.Context(), iam.SessionParams{
		SubjectID: u.ID,
		Kind:      iam.KindUser,
		Method:    method,
		TTL:       sessionTTL,
	})
	if err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	http.SetCookie(w, a.cfg.IAM.SessionCookie(token, derefTime(sess.ExpiresAt)))
	a.rememberDevice(w, r, u)
	iam.WriteOK(w)
}

// rejectLogin writes a uniform bad-credentials response; ErrInactive keeps
// its own status so the client can tell the account apart.
func (a *authAPI) rejectLogin(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, iam.ErrInactive):
		iam.WriteError(w, http.StatusForbidden, "inactive", "this account has been deactivated")
	default:
		iam.WriteError(w, http.StatusUnauthorized, "bad_credentials", "invalid email or password")
	}
}

func (a *authAPI) logout(w http.ResponseWriter, r *http.Request) {
	if token := iam.SessionTokenFromRequest(r); token != "" {
		_ = a.cfg.IAM.Sessions.Revoke(r.Context(), token)
	}
	http.SetCookie(w, a.cfg.IAM.ClearSessionCookie())
	iam.WriteOK(w)
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

func (a *authAPI) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	// Unknown email, unverified email, and disabled reset all answer 200 so
	// the endpoint cannot enumerate accounts.
	if u, err := a.cfg.IAM.GetUserByEmail(r.Context(), req.Email); err == nil &&
		u.Active && !u.DisablePasswordReset {
		a.sendTokenEmail(r, u, iam.TokenPasswordReset, false)
	}
	iam.WriteOK(w)
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func (a *authAPI) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	if len(req.NewPassword) < 8 || len(req.NewPassword) > maxPasswordLength {
		iam.WriteError(
			w,
			http.StatusBadRequest,
			"password_too_short",
			"password must be at least 8 characters",
		)
		return
	}
	userID, purpose, err := a.cfg.IAM.ConsumeToken(r.Context(), req.Token)
	if err != nil || purpose != iam.TokenPasswordReset {
		iam.WriteError(
			w,
			http.StatusBadRequest,
			"invalid_token",
			"this reset link is invalid or expired",
		)
		return
	}
	if err := a.cfg.IAM.Password.SetPassword(r.Context(), userID, req.NewPassword); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteOK(w)
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

func (a *authAPI) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	userID, purpose, err := a.cfg.IAM.ConsumeToken(r.Context(), req.Token)
	if err != nil || purpose != iam.TokenVerifyEmail {
		iam.WriteError(
			w,
			http.StatusBadRequest,
			"invalid_token",
			"this verification link is invalid or expired",
		)
		return
	}
	if err := a.cfg.IAM.VerifyUserEmail(r.Context(), userID); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteOK(w)
}

type resendVerificationRequest struct {
	Email string `json:"email"`
}

func (a *authAPI) resendVerification(w http.ResponseWriter, r *http.Request) {
	var req resendVerificationRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	// Unknown and already-verified accounts answer 200 so the endpoint
	// cannot enumerate accounts.
	if u, err := a.cfg.IAM.GetUserByEmail(r.Context(), req.Email); err == nil && !u.EmailVerified {
		a.sendTokenEmail(r, u, iam.TokenVerifyEmail, false)
	}
	iam.WriteOK(w)
}

// sendTokenEmail mints a one-time token and delivers it as a welcome or
// recovery email with a signed-out link. Delivery failures are logged, not
// returned: the email is a side effect of the flow.
func (a *authAPI) sendTokenEmail(r *http.Request, u *db.User, purpose string, welcome bool) {
	raw, err := a.cfg.IAM.IssueToken(r.Context(), u.ID, purpose, tokenTTL)
	if err != nil {
		return
	}
	path := "/verify"
	if purpose == iam.TokenPasswordReset {
		path = "/reset"
	}
	link := a.cfg.FullURL() + path + "?token=" + raw

	ctx := r.Context()
	name, _, _ := strings.Cut(u.Email, "@")
	if welcome {
		err = a.cfg.Email.SendWelcomeEmail(ctx, u.ID, u.Email, name, link, tokenTTL.String())
	} else {
		err = a.cfg.Email.SendRecoveryEmail(ctx, u.ID, u.Email, link, tokenTTL.String())
	}
	if err != nil {
		slog.Error("send auth email", "error", err)
	}
}

// ssoDiscover resolves the SSO provider for an email's domain: the login
// page shows the SSO button (and hides the password form on enforce) when a
// verified domain binds the workspace to a provider. SSO login start and
// callbacks are the P4 flows; discovery already answers correctly.
func (a *authAPI) ssoDiscover(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"hasSSO":    false,
		"enforce":   false,
		"providers": []map[string]any{},
	}

	email := r.URL.Query().Get("email")
	_, domain, ok := strings.Cut(email, "@")
	if !ok || domain == "" {
		iam.WriteJSON(w, http.StatusOK, out)
		return
	}

	d, err := a.cfg.IAM.GetVerifiedTenantDomain(r.Context(), strings.ToLower(domain))
	if err != nil {
		iam.WriteJSON(w, http.StatusOK, out)
		return
	}

	p, err := a.cfg.IAM.GetSSOProvider(r.Context(), d.ProviderID)
	if err != nil || !p.Enabled {
		iam.WriteJSON(w, http.StatusOK, out)
		return
	}

	out["hasSSO"] = true
	if p.OIDC != nil {
		out["enforce"] = p.OIDC.EnforceSSO
	} else if p.SAML != nil {
		out["enforce"] = p.SAML.EnforceSSO
	}
	out["providers"] = []map[string]any{{
		"method":   string(p.Method),
		"provider": p.ProviderID,
		"name":     p.Name,
	}}
	iam.WriteJSON(w, http.StatusOK, out)
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
