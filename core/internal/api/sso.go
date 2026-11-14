package api

import (
	"context"
	"errors"
	"net/url"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

type ssoService struct {
	cfg *app.Config
}

func (s *ssoService) ListSSOProviders(
	ctx context.Context,
	_ *nokkuv1.ListSSOProvidersRequest,
) (*nokkuv1.ListSSOProvidersResponse, error) {
	providers, err := s.cfg.IAM.ListSSOProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*nokkuv1.SSOProvider, 0, len(providers))
	for i := range providers {
		out = append(out, providerToProto(&providers[i]))
	}
	return &nokkuv1.ListSSOProvidersResponse{Providers: out, RedirectUri: new(iam.RedirectURI(ctx))}, nil
}

func (s *ssoService) PutSSOProvider(
	ctx context.Context,
	req *nokkuv1.PutSSOProviderRequest,
) (*nokkuv1.PutSSOProviderResponse, error) {
	// On plain http whoever sits on the path could sign in as anyone.
	if s.cfg.SaaS {
		if u, err := url.Parse(req.GetIssuerUrl()); err != nil || u.Scheme != "https" {
			return nil, connect.NewError(connect.CodeInvalidArgument, "the issuer URL has to start with https://")
		}
	}
	// Only a new issuer is fetched, so a down provider can still be edited.
	prev, err := s.cfg.IAM.GetSSOProvider(ctx, req.GetProviderId())
	if err != nil || prev.OIDC.IssuerURL != req.GetIssuerUrl() {
		if err := s.cfg.IAM.CheckIssuer(ctx, req.GetIssuerUrl()); err != nil {
			return nil, connect.NewError(
				connect.CodeInvalidArgument,
				"the issuer URL did not answer with an OpenID Connect discovery document: "+err.Error(),
			)
		}
	}
	stored, err := s.cfg.IAM.PutSSOProvider(ctx, iam.SSOProvider{
		ProviderID: req.GetProviderId(),
		Name:       req.GetName(),
		Enabled:    req.GetEnabled(),
		OIDC: iam.OIDCProvider{
			IssuerURL:            req.GetIssuerUrl(),
			ClientID:             req.GetClientId(),
			ClientSecret:         req.GetClientSecret(),
			Scopes:               req.GetScopes(),
			JITProvisioning:      req.GetJitProvisioning(),
			TrustUnverifiedEmail: req.GetTrustUnverifiedEmail(),
		},
	})
	if errors.Is(err, iam.ErrSecretRequired) {
		return nil, connect.NewError(
			connect.CodeInvalidArgument,
			"enter the client secret again when the issuer URL changes",
		)
	}
	if err != nil {
		return nil, err
	}
	return &nokkuv1.PutSSOProviderResponse{Provider: providerToProto(stored)}, nil
}

func (s *ssoService) DeleteSSOProvider(
	ctx context.Context,
	req *nokkuv1.DeleteSSOProviderRequest,
) (*nokkuv1.DeleteSSOProviderResponse, error) {
	err := s.cfg.IAM.DeleteSSOProvider(ctx, req.GetProviderId())
	if errors.Is(err, iam.ErrNotFound) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteSSOProviderResponse{}, nil
}

func providerToProto(p *iam.SSOProvider) *nokkuv1.SSOProvider {
	return &nokkuv1.SSOProvider{
		ProviderId:           &p.ProviderID,
		Name:                 &p.Name,
		Enabled:              &p.Enabled,
		IssuerUrl:            &p.OIDC.IssuerURL,
		ClientId:             &p.OIDC.ClientID,
		Scopes:               p.OIDC.Scopes,
		JitProvisioning:      &p.OIDC.JITProvisioning,
		TrustUnverifiedEmail: &p.OIDC.TrustUnverifiedEmail,
		CreatedAt:            db.SafeTimestamp(&p.CreatedAt),
		UpdatedAt:            db.SafeTimestamp(&p.UpdatedAt),
	}
}
