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
)

const (
	tokenTTL = 15 * time.Minute
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
	ci, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}

	u, cookie, err := s.cfg.IAM.Password.Login(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, loginError(err)
	}
	setCookie(ci, cookie)
	if c := s.cfg.IAM.RememberDevice(ctx, ci.RequestHeader(), ci.Peer().Addr, u); c != nil {
		setCookie(ci, c)
	}
	return &nokkuv1.LoginResponse{User: u.ToProto()}, nil
}

func (s *AuthService) LoginWithBackupCode(
	ctx context.Context,
	req *nokkuv1.LoginWithBackupCodeRequest,
) (*nokkuv1.LoginWithBackupCodeResponse, error) {
	ci, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}

	u, cookie, err := s.cfg.IAM.LoginWithBackupCode(ctx, req.GetEmail(), req.GetCode())
	if err != nil {
		return nil, loginError(err)
	}
	setCookie(ci, cookie)
	if c := s.cfg.IAM.RememberDevice(ctx, ci.RequestHeader(), ci.Peer().Addr, u); c != nil {
		setCookie(ci, c)
	}
	return &nokkuv1.LoginWithBackupCodeResponse{User: u.ToProto()}, nil
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
		_ = s.cfg.IAM.RevokeSession(ctx, token)
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

// sendTokenEmail issues the verification or reset token and delivers its
// email link, unless the same token was just sent.
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
