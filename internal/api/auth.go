package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

const tokenTTL = 15 * time.Minute

type authService struct {
	cfg *config.Config
}

func newAuthService(cfg *config.Config) *authService {
	return &authService{cfg: cfg}
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

func (s *authService) Register(
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
			return nil, newError(
				connect.CodeAlreadyExists,
				"an account with this email already exists",
			)
		}
		if errors.Is(err, iam.ErrEmailRejected) {
			return nil, newError(
				connect.CodeInvalidArgument,
				"please enter a valid email address",
			)
		}
		return nil, errInternal
	}
	s.sendTokenEmail(ctx, u, iam.TokenVerifyEmail, true)
	return &nokkuv1.RegisterResponse{}, nil
}

func (s *authService) Login(
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

func (s *authService) LoginWithBackupCode(
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

func loginError(err error) error {
	if errors.Is(err, iam.ErrInactive) {
		return errAccountInactive
	}
	if errors.Is(err, iam.ErrEmailUnverified) {
		return errEmailUnverified
	}
	if errors.Is(err, iam.ErrSSORequired) {
		return errSSORequired
	}
	if errors.Is(err, iam.ErrTooManyAttempts) {
		return errTooManyAttempts
	}
	return errLoginFailed
}

func (s *authService) Logout(
	ctx context.Context,
	_ *nokkuv1.LogoutRequest,
) (*nokkuv1.LogoutResponse, error) {
	ci, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	// Public endpoint, so authenticate the credential here before revoking.
	setCookie(ci, s.cfg.IAM.ClearSessionCookie())
	if err := s.cfg.IAM.Logout(ctx, ci.RequestHeader(), nokkuv1connect.AuthServiceLogoutProcedure); err != nil {
		if errors.Is(err, iam.ErrDPoPNonce) || errors.Is(err, iam.ErrDPoPRequired) {
			s.cfg.IAM.AdvertiseDPoPNonce(ci.ResponseHeader())
			return nil, connect.NewError(connect.CodeUnauthenticated, err)
		}
		return nil, errInternal
	}
	return &nokkuv1.LogoutResponse{}, nil
}

func (s *authService) ForgotPassword(
	ctx context.Context,
	req *nokkuv1.ForgotPasswordRequest,
) (*nokkuv1.ForgotPasswordResponse, error) {
	// Always answer OK so the endpoint cannot enumerate accounts.
	if u, err := s.cfg.IAM.GetUserByEmail(ctx, req.GetEmail()); err == nil &&
		u.Active && !u.DisablePasswordReset {
		s.sendTokenEmail(ctx, u, iam.TokenPasswordReset, false)
	}
	return &nokkuv1.ForgotPasswordResponse{}, nil
}

func (s *authService) ResetPassword(
	ctx context.Context,
	req *nokkuv1.ResetPasswordRequest,
) (*nokkuv1.ResetPasswordResponse, error) {
	userID, err := s.cfg.IAM.ConsumeToken(ctx, req.GetToken(), iam.TokenPasswordReset)
	if err != nil {
		return nil, newError(
			connect.CodeInvalidArgument,
			"this reset link is invalid or expired",
		)
	}
	if err := s.cfg.IAM.Password.SetPassword(ctx, userID, req.GetNewPassword()); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.ResetPasswordResponse{}, nil
}

func (s *authService) VerifyEmail(
	ctx context.Context,
	req *nokkuv1.VerifyEmailRequest,
) (*nokkuv1.VerifyEmailResponse, error) {
	userID, err := s.cfg.IAM.ConsumeToken(ctx, req.GetToken(), iam.TokenVerifyEmail)
	if err != nil {
		return nil, newError(
			connect.CodeInvalidArgument,
			"this verification link is invalid or expired",
		)
	}
	if err := s.cfg.IAM.VerifyUserEmail(ctx, userID); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.VerifyEmailResponse{}, nil
}

func (s *authService) ResendVerification(
	ctx context.Context,
	req *nokkuv1.ResendVerificationRequest,
) (*nokkuv1.ResendVerificationResponse, error) {
	// Always answer OK so the endpoint cannot enumerate accounts.
	// Welcome goes out once at signup, a resend is a plain verification.
	if u, err := s.cfg.IAM.GetUserByEmail(ctx, req.GetEmail()); err == nil && !u.EmailVerified {
		s.sendTokenEmail(ctx, u, iam.TokenVerifyEmail, false)
	}
	return &nokkuv1.ResendVerificationResponse{}, nil
}

func (s *authService) ConfirmEmailChange(
	ctx context.Context,
	req *nokkuv1.ConfirmEmailChangeRequest,
) (*nokkuv1.ConfirmEmailChangeResponse, error) {
	err := s.cfg.IAM.ConfirmEmailChange(ctx, req.GetToken())
	if errors.Is(err, iam.ErrEmailTaken) {
		return nil, newError(connect.CodeAlreadyExists, "an account with this email already exists")
	}
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "this confirmation link is invalid or expired")
	}
	return &nokkuv1.ConfirmEmailChangeResponse{}, nil
}

func (s *authService) CancelEmailChange(
	ctx context.Context,
	req *nokkuv1.CancelEmailChangeRequest,
) (*nokkuv1.CancelEmailChangeResponse, error) {
	err := s.cfg.IAM.CancelEmailChange(ctx, req.GetToken())
	if errors.Is(err, iam.ErrEmailTaken) {
		return nil, newError(
			connect.CodeAlreadyExists,
			"another account uses the old address by now, contact support",
		)
	}
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "this link is invalid or expired")
	}
	return &nokkuv1.CancelEmailChangeResponse{}, nil
}

func (s *authService) DiscoverSSO(
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

	p, err := s.cfg.IAM.GetSSOProvider(ctx, d.WorkspaceID)
	if err != nil || !p.Enabled {
		return out, nil
	}

	out.HasSso = new(true)
	out.Enforce = new(p.Enforced())
	out.Providers = []*nokkuv1.SSOProviderInfo{{
		Method:   new(string(p.Method)),
		Provider: new(p.ProviderID),
		Name:     new(p.Name),
	}}
	return out, nil
}

// sendTokenEmail skips the send when the same token went out recently.
func (s *authService) sendTokenEmail(
	ctx context.Context,
	u *db.User,
	purpose string,
	welcome bool,
) {
	recent, err := s.cfg.IAM.HasRecentToken(ctx, u.ID, purpose)
	if err != nil {
		// Fail open, the worst case is an extra email.
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

	switch {
	case welcome:
		name, _, _ := strings.Cut(u.Email, "@")
		err = s.cfg.Email.SendWelcomeEmail(ctx, u.ID, u.Email, name, link, tokenTTL.String())
	case purpose == iam.TokenPasswordReset:
		err = s.cfg.Email.SendRecoveryEmail(ctx, u.ID, u.Email, link, tokenTTL.String())
	default:
		err = s.cfg.Email.SendVerificationEmail(ctx, u.ID, u.Email, link, tokenTTL.String())
	}
	if err != nil {
		slog.Error("send auth email", "error", err)
	}
}
