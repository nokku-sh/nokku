package api

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

type authService struct {
	cfg *config.Config
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

func (s *authService) GetLoginOptions(
	ctx context.Context,
	_ *nokkuv1.GetLoginOptionsRequest,
) (*nokkuv1.GetLoginOptionsResponse, error) {
	ws, err := s.cfg.Conn.Tenant().GetWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	enforced := ws.Settings.GetEnforceSso()
	providers, err := s.cfg.IAM.ListSSOProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := &nokkuv1.GetLoginOptionsResponse{
		WorkspaceName:   &ws.Name,
		MagicLink:       new(!enforced && s.cfg.IAM.MagicLinkEnabled()),
		Passkey:         new(!enforced),
		EmailConfigured: new(s.cfg.IAM.MagicLinkEnabled()),
		Providers:       []*nokkuv1.SSOProviderInfo{},
	}
	for _, p := range providers {
		if p.Enabled {
			out.Providers = append(out.Providers, &nokkuv1.SSOProviderInfo{ProviderId: &p.ProviderID, Name: &p.Name})
		}
	}
	return out, nil
}

// RequestMagicLink always answers OK so it cannot enumerate accounts.
func (s *authService) RequestMagicLink(
	ctx context.Context,
	req *nokkuv1.RequestMagicLinkRequest,
) (*nokkuv1.RequestMagicLinkResponse, error) {
	s.cfg.IAM.RequestMagicLink(ctx, req.GetEmail())
	return &nokkuv1.RequestMagicLinkResponse{}, nil
}

func (s *authService) ConsumeMagicLink(
	ctx context.Context,
	req *nokkuv1.ConsumeMagicLinkRequest,
) (*nokkuv1.ConsumeMagicLinkResponse, error) {
	ci, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	u, cookie, err := s.cfg.IAM.ConsumeMagicLink(ctx, req.GetToken())
	switch {
	case errors.Is(err, iam.ErrInactive):
		return nil, errAccountInactive
	case errors.Is(err, iam.ErrSSORequired):
		return nil, errSSORequired
	case errors.Is(err, iam.ErrSeatLimit):
		return nil, newError(connect.CodeResourceExhausted, "this workspace has no seats left")
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, newError(connect.CodeAlreadyExists, "an account with this email already exists, sign in instead")
	case err != nil:
		return nil, errLinkInvalid
	}
	setCookie(ci, cookie)
	if c := s.cfg.IAM.RememberDevice(ctx, ci.RequestHeader(), ci.Peer().Addr, u); c != nil {
		setCookie(ci, c)
	}
	return &nokkuv1.ConsumeMagicLinkResponse{User: u.ToProto()}, nil
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
			s.cfg.IAM.AdvertiseDPoPNonce(ctx, ci.ResponseHeader())
			return nil, connect.NewError(connect.CodeUnauthenticated, err)
		}
		return nil, errInternal
	}
	return &nokkuv1.LogoutResponse{}, nil
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
			"another account uses the old address by now, contact your administrator",
		)
	}
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "this link is invalid or expired")
	}
	return &nokkuv1.CancelEmailChangeResponse{}, nil
}
