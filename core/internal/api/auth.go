package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/dpop"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

const actionExchangeWorkloadToken = "ExchangeWorkloadToken"

type authService struct {
	cfg *config.Config
}

func callInfo(ctx context.Context) (*connect.CallInfo, error) {
	ci, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return nil, connect.NewError(
			connect.CodeInternal,
			"no call info in context",
		)
	}
	return ci, nil
}

func setCookie(ci *connect.CallInfo, c *http.Cookie) {
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
	// The rows alone. Anyone may load this page, it opens no provider's config.
	providers, err := s.cfg.Conn.Tenant().ListSSOProviders(ctx)
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
		return nil, errSeatLimit
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, newError(connect.CodeAlreadyExists, "an account with this email already exists, sign in instead")
	case err != nil:
		return nil, errLinkInvalid
	}
	setCookie(ci, cookie)
	meta, _ := actor.RequestMetaFromContext(ctx)
	if c := s.cfg.IAM.RememberDevice(ctx, meta.Header, meta.RemoteAddr, u); c != nil {
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
	meta, _ := actor.RequestMetaFromContext(ctx)
	if err := s.cfg.IAM.Logout(ctx, meta.Header, nokkuv1connect.AuthServiceLogoutProcedure); err != nil {
		if errors.Is(err, dpop.ErrNonce) || errors.Is(err, iam.ErrDPoPRequired) {
			s.cfg.IAM.AdvertiseDPoPNonce(ctx, ci.ResponseHeader())
			return nil, connect.NewError(connect.CodeUnauthenticated, err.Error()).WithCause(err)
		}
		return nil, err
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

// ExchangeWorkloadToken trades a job's token for a session of a service account, bound to the key of the proof. The
// call is public, so it runs the plan gate itself and writes its own audit row.
func (s *authService) ExchangeWorkloadToken(
	ctx context.Context,
	req *nokkuv1.ExchangeWorkloadTokenRequest,
) (*nokkuv1.ExchangeWorkloadTokenResponse, error) {
	ci, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	// First, so a client that has to sign again has not spent its job token.
	binding, err := s.workloadBinding(ctx)
	if errors.Is(err, dpop.ErrNonce) {
		s.cfg.IAM.AdvertiseDPoPNonce(ctx, ci.ResponseHeader())
		return nil, newError(connect.CodeUnauthenticated, "stale DPoP nonce")
	}
	if err != nil {
		return nil, s.refuseWorkload(ctx, &iam.WorkloadRefusedError{Reason: "no valid DPoP proof"})
	}

	job, err := s.cfg.IAM.VerifyWorkload(ctx, req.GetServiceAccount(), req.GetToken())
	if refusal, ok := errors.AsType[*iam.WorkloadRefusedError](err); ok {
		return nil, s.refuseWorkload(ctx, refusal)
	}
	if err != nil {
		return nil, err
	}
	if err := s.cfg.Entitlements.CheckSigning(ctx); err != nil {
		return nil, s.refuseWorkload(ctx, &iam.WorkloadRefusedError{
			Account: job.Account, Reason: "the plan of the workspace does not sign", Signed: true,
		})
	}
	tok, secret, err := s.cfg.IAM.IssueWorkloadSession(ctx, job, binding)
	if refusal, ok := errors.AsType[*iam.WorkloadRefusedError](err); ok {
		return nil, s.refuseWorkload(ctx, refusal)
	}
	if err != nil {
		return nil, err
	}

	// IssueToken writes no row for a service account. A session nobody heard of must not go out, it stays unused.
	if err := s.cfg.Audit.Confirm(ctx, &audit.Event{
		Action:    actionExchangeWorkloadToken,
		ActorID:   job.Account.ID,
		ActorKind: string(actor.KindServiceAccount),
		ActorName: job.Account.Name,
		Target:    tok.ID,
		Details: map[string]any{
			"method":     string(iam.MethodFederation),
			"issuer":     job.Rule.Issuer,
			"rule":       job.Rule.ID,
			"subject":    job.Subject,
			"jti":        job.JTI,
			"expires_at": *tok.ExpiresAt,
		},
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.ExchangeWorkloadTokenResponse{
		AccessToken: &secret,
		ExpiresAt:   timestamppb.New(*tok.ExpiresAt),
	}, nil
}

// workloadBinding returns the thumbprint of the key that signed the proof. No token exists yet, so nothing binds it.
func (s *authService) workloadBinding(ctx context.Context) (string, error) {
	ws, _ := actor.WorkspaceFromContext(ctx)
	meta, _ := actor.RequestMetaFromContext(ctx)
	proof, err := dpop.ProofFrom(meta.Header)
	if err != nil {
		return "", err
	}
	return s.cfg.IAM.DPoP.Verify(
		proof,
		"",
		http.MethodPost,
		ws.BaseURL+nokkuv1connect.AuthServiceExchangeWorkloadTokenProcedure,
		"",
	)
}

// refuseWorkload keeps the reason here, the job gets one answer for every refusal. The call is public, so only a token
// its issuer signed reaches the audit log. Nobody fills the log of a workspace at the rate limit.
func (s *authService) refuseWorkload(ctx context.Context, r *iam.WorkloadRefusedError) error {
	e := &audit.Event{
		Action:    actionExchangeWorkloadToken,
		ActorKind: string(actor.KindServiceAccount),
		Details: map[string]any{
			"method": string(iam.MethodFederation),
			"reason": r.Reason,
			"code":   connect.CodeUnauthenticated.String(),
		},
	}
	if r.Account != nil {
		e.ActorID, e.ActorName = r.Account.ID, r.Account.Name
	}
	slog.WarnContext(ctx, "workload token refused", "service_account", e.ActorName, "reason", r.Reason)
	if r.Signed {
		s.cfg.Audit.Record(ctx, e)
	}
	return errWorkloadRefused
}
