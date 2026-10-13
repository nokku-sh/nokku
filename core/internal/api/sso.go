package api

import (
	"context"
	"errors"
	"net/url"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

type ssoService struct {
	cfg *config.Config
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
	return &nokkuv1.ListSSOProvidersResponse{Providers: out}, nil
}

func (s *ssoService) PutSSOProvider(
	ctx context.Context,
	req *nokkuv1.PutSSOProviderRequest,
) (*nokkuv1.PutSSOProviderResponse, error) {
	// The hosted service only reaches a provider over TLS. On plain http whoever sits on the path signs in as anyone.
	if s.cfg.SaaS {
		if u, err := url.Parse(req.GetIssuerUrl()); err != nil || u.Scheme != "https" {
			return nil, newError(connect.CodeInvalidArgument, "the issuer URL has to start with https://")
		}
	}
	stored, err := s.cfg.IAM.PutSSOProvider(ctx, iam.SSOProvider{
		ProviderID: req.GetProviderId(),
		Name:       req.GetName(),
		Enabled:    req.GetEnabled(),
		OIDC: iam.OIDCProvider{
			IssuerURL:       req.GetIssuerUrl(),
			ClientID:        req.GetClientId(),
			ClientSecret:    req.GetClientSecret(),
			Scopes:          req.GetScopes(),
			JITProvisioning: req.GetJitProvisioning(),
		},
	})
	if errors.Is(err, iam.ErrSecretRequired) {
		return nil, newError(connect.CodeInvalidArgument, "enter the client secret again when the issuer URL changes")
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
		ProviderId:      &p.ProviderID,
		Name:            &p.Name,
		Enabled:         &p.Enabled,
		IssuerUrl:       &p.OIDC.IssuerURL,
		ClientId:        &p.OIDC.ClientID,
		Scopes:          p.OIDC.Scopes,
		JitProvisioning: &p.OIDC.JITProvisioning,
		CreatedAt:       db.SafeTimestamp(&p.CreatedAt),
		UpdatedAt:       db.SafeTimestamp(&p.UpdatedAt),
	}
}
