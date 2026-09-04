package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/util"
)

const (
	tokenTTL         = 15 * time.Minute
	sessionTTL       = 24 * time.Hour
	deviceCookieName = "nokku_device"
	deviceSessionTTL = 180 * 24 * time.Hour // 6 months, refreshed on each login
)

type AuthService struct {
	cfg *config.Config
}

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{cfg: cfg}
}

func callInfo(ctx context.Context) (connect.CallInfo, error) {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, connect.NewError(
			connect.CodeInternal,
			errors.New("no call info in context"),
		)
	}
	return ci, nil
}

func setCookie(ci connect.CallInfo, c *http.Cookie) {
	ci.ResponseHeader().Add("Set-Cookie", c.String())
}

func (s *AuthService) Register(
	ctx context.Context,
	req *nokkuv1.RegisterRequest,
) (*nokkuv1.RegisterResponse, error) {
	u, err := s.cfg.IAM.Register(
		ctx,
		strings.ToLower(strings.TrimSpace(req.GetEmail())),
		strings.TrimSpace(req.GetName()),
		req.GetPassword(),
	)
	if err != nil {
		if errors.Is(err, iam.ErrEmailTaken) {
			return nil, NewError(
				connect.CodeAlreadyExists,
				"an account with this email already exists",
			)
		}
		if errors.Is(err, iam.ErrEmailRejected) {
			return nil, NewError(
				connect.CodeInvalidArgument,
				"please enter a valid email address",
			)
		}
		return nil, ErrInternal
	}
	// Field shape is the proto schema's business (validate interceptor);
	// normalization above is the handler's.
	s.sendTokenEmail(ctx, u, iam.TokenVerifyEmail, true)
	return &nokkuv1.RegisterResponse{}, nil
}

func (s *AuthService) Login(
	ctx context.Context,
	req *nokkuv1.LoginRequest,
) (*nokkuv1.LoginResponse, error) {
	u, err := s.cfg.IAM.Password.Login(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, loginError(err)
	}
	if err := s.issueSession(ctx, u, iam.MethodPassword); err != nil {
		return nil, err
	}
	return &nokkuv1.LoginResponse{User: db.UserToProto(u)}, nil
}

func (s *AuthService) LoginWithBackupCode(
	ctx context.Context,
	req *nokkuv1.LoginWithBackupCodeRequest,
) (*nokkuv1.LoginWithBackupCodeResponse, error) {
	u, err := s.cfg.IAM.LoginWithBackupCode(ctx, req.GetEmail(), req.GetCode())
	if err != nil {
		return nil, loginError(err)
	}
	if err := s.issueSession(ctx, u, iam.MethodBackupCode); err != nil {
		return nil, err
	}
	return &nokkuv1.LoginWithBackupCodeResponse{User: db.UserToProto(u)}, nil
}

// issueSession creates the web session, writes the cookie, and reconciles
// the remembered device (new device => one geo-located security alert).
func (s *AuthService) issueSession(ctx context.Context, u *db.User, method iam.Method) error {
	ci, err := callInfo(ctx)
	if err != nil {
		return err
	}
	sess, token, err := s.cfg.IAM.Sessions.Issue(ctx, iam.SessionParams{
		SubjectID: u.ID,
		Kind:      iam.KindUser,
		Method:    method,
		TTL:       sessionTTL,
	})
	if err != nil {
		return ErrInternal
	}
	setCookie(ci, s.cfg.IAM.SessionCookie(token, derefTime(sess.ExpiresAt)))
	if c := s.reconcileDevice(ctx, ci.RequestHeader(), ci.Peer().Addr, u); c != nil {
		setCookie(ci, c)
	}
	return nil
}

// loginError writes a uniform bad-credentials response; ErrInactive keeps
// its own code so the client can tell the account apart.
func loginError(err error) error {
	if errors.Is(err, iam.ErrInactive) {
		return ErrAccountInactive
	}
	if errors.Is(err, iam.ErrEmailUnverified) {
		return ErrEmailUnverified
	}
	return ErrLoginFailed
}

func (s *AuthService) Logout(
	ctx context.Context,
	_ *nokkuv1.LogoutRequest,
) (*nokkuv1.LogoutResponse, error) {
	ci, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	// Public endpoint, so the session arrives as a cookie rather than a
	// principal. Revoke when present, always clear the cookie: logout must
	// succeed on a stale or expired session too.
	if token := iam.SessionTokenFromHeader(ci.RequestHeader()); token != "" {
		_ = s.cfg.IAM.Sessions.Revoke(ctx, token)
	}
	setCookie(ci, s.cfg.IAM.ClearSessionCookie())
	return &nokkuv1.LogoutResponse{}, nil
}

func (s *AuthService) ForgotPassword(
	ctx context.Context,
	req *nokkuv1.ForgotPasswordRequest,
) (*nokkuv1.ForgotPasswordResponse, error) {
	// Unknown email, unverified email, and disabled reset all answer OK so
	// the endpoint cannot enumerate accounts.
	if u, err := s.cfg.IAM.GetUserByEmail(ctx, req.GetEmail()); err == nil &&
		u.Active && !u.DisablePasswordReset {
		s.sendTokenEmail(ctx, u, iam.TokenPasswordReset, false)
	}
	return &nokkuv1.ForgotPasswordResponse{}, nil
}

func (s *AuthService) ResetPassword(
	ctx context.Context,
	req *nokkuv1.ResetPasswordRequest,
) (*nokkuv1.ResetPasswordResponse, error) {
	userID, purpose, err := s.cfg.IAM.ConsumeToken(ctx, req.GetToken())
	if err != nil || purpose != iam.TokenPasswordReset {
		return nil, NewError(
			connect.CodeInvalidArgument,
			"this reset link is invalid or expired",
		)
	}
	if err := s.cfg.IAM.Password.SetPassword(ctx, userID, req.GetNewPassword()); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.ResetPasswordResponse{}, nil
}

func (s *AuthService) VerifyEmail(
	ctx context.Context,
	req *nokkuv1.VerifyEmailRequest,
) (*nokkuv1.VerifyEmailResponse, error) {
	userID, purpose, err := s.cfg.IAM.ConsumeToken(ctx, req.GetToken())
	if err != nil || purpose != iam.TokenVerifyEmail {
		return nil, NewError(
			connect.CodeInvalidArgument,
			"this verification link is invalid or expired",
		)
	}
	if err := s.cfg.IAM.VerifyUserEmail(ctx, userID); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.VerifyEmailResponse{}, nil
}

func (s *AuthService) ResendVerification(
	ctx context.Context,
	req *nokkuv1.ResendVerificationRequest,
) (*nokkuv1.ResendVerificationResponse, error) {
	// Unknown and already-verified accounts answer OK so the endpoint
	// cannot enumerate accounts.
	if u, err := s.cfg.IAM.GetUserByEmail(ctx, req.GetEmail()); err == nil && !u.EmailVerified {
		s.sendTokenEmail(ctx, u, iam.TokenVerifyEmail, true)
	}
	return &nokkuv1.ResendVerificationResponse{}, nil
}

func (s *AuthService) DiscoverSSO(
	ctx context.Context,
	req *nokkuv1.DiscoverSSORequest,
) (*nokkuv1.DiscoverSSOResponse, error) {
	out := &nokkuv1.DiscoverSSOResponse{Providers: []*nokkuv1.SSOProviderInfo{}}

	_, domain, ok := strings.Cut(req.GetEmail(), "@")
	if !ok || domain == "" {
		return out, nil
	}

	d, err := s.cfg.IAM.GetVerifiedTenantDomain(ctx, strings.ToLower(domain))
	if err != nil {
		return out, nil
	}

	p, err := s.cfg.IAM.GetSSOProvider(ctx, d.ProviderID)
	if err != nil || !p.Enabled {
		return out, nil
	}

	out.HasSso = new(true)
	if p.OIDC != nil {
		out.Enforce = new(p.OIDC.EnforceSSO)
	} else if p.SAML != nil {
		out.Enforce = new(p.SAML.EnforceSSO)
	}
	out.Providers = []*nokkuv1.SSOProviderInfo{{
		Method:   new(string(p.Method)),
		Provider: new(p.ProviderID),
		Name:     new(p.Name),
	}}
	return out, nil
}

// --- Shared login side effects ----------------------------------------------

// reconcileDevice reads the remembered-device cookie from header and returns
// the refreshed or freshly issued device cookie, or nil. The geo-located
// new-login alert (one per new device) is a side effect.
func (s *AuthService) reconcileDevice(
	ctx context.Context,
	h http.Header,
	remoteAddr string,
	u *db.User,
) *http.Cookie {
	if raw := iam.CookieFromHeader(h, deviceCookieName); raw != "" {
		if sess, err := s.cfg.IAM.Sessions.Verify(ctx, raw); err == nil &&
			sess.Kind == string(iam.KindWebDevice) && sess.SubjectID == u.ID {
			// Known device: refresh its last-seen time so the sessions list
			// shows current activity. No alert.
			if err := s.cfg.IAM.Sessions.Touch(
				ctx,
				iam.SessionHash(sess.TokenHash),
			); err != nil {
				slog.Debug("failed to touch device session", "error", err)
			}
			return nil
		}
	}

	name := iam.DeviceNameFromUA(h.Get("User-Agent"))
	sess, token, err := s.cfg.IAM.Sessions.Issue(ctx, iam.SessionParams{
		SubjectID: u.ID,
		Kind:      iam.KindWebDevice,
		Method:    iam.MethodDevice,
		Label:     name,
		TTL:       deviceSessionTTL,
	})
	if err != nil {
		slog.Error("failed to register device session", "error", err)
		return nil
	}

	ip := util.GetRemoteIP(h, remoteAddr)
	go func() {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.cfg.Email.SendNewLoginEmail(
			actx,
			u.ID,
			u.Email,
			string(sess.TokenHash),
			name,
			s.cfg.Geo.Lookup(ip),
		); err != nil {
			slog.Debug("failed to send new login email", "error", err)
		}
	}()

	return &http.Cookie{ //nolint:gosec // Secure is set dynamically from the base URL scheme
		Name:     deviceCookieName,
		Value:    token,
		Path:     "/",
		Expires:  derefTime(sess.ExpiresAt),
		HttpOnly: true,
		Secure:   s.cfg.IAM.Secure(),
		SameSite: http.SameSiteLaxMode,
	}
}

func (s *AuthService) sendTokenEmail(
	ctx context.Context,
	u *db.User,
	purpose string,
	welcome bool,
) {
	recent, err := s.cfg.IAM.HasRecentToken(ctx, u.ID, purpose)
	if err != nil {
		// Fail open: the worst case is an extra email, not a locked-out user.
		slog.Debug("resend cooldown check failed", "error", err)
	} else if recent {
		return
	}
	raw, err := s.cfg.IAM.IssueToken(ctx, u.ID, purpose, tokenTTL)
	if err != nil {
		return
	}
	path := "/verify"
	if purpose == iam.TokenPasswordReset {
		path = "/reset"
	}
	link := s.cfg.FullURL() + path + "?token=" + raw

	name, _, _ := strings.Cut(u.Email, "@")
	if welcome {
		err = s.cfg.Email.SendWelcomeEmail(ctx, u.ID, u.Email, name, link, tokenTTL.String())
	} else {
		err = s.cfg.Email.SendRecoveryEmail(ctx, u.ID, u.Email, link, tokenTTL.String())
	}
	if err != nil {
		slog.Error("send auth email", "error", err)
	}
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
