package api

import (
	"context"
	"errors"
	"log/slog"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

// sSOService manages the OIDC providers of the workspace.
type sSOService struct {
	cfg *config.Config
}

func (s *sSOService) ListSSOProviders(
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

func (s *sSOService) PutSSOProvider(
	ctx context.Context,
	req *nokkuv1.PutSSOProviderRequest,
) (*nokkuv1.PutSSOProviderResponse, error) {
	// sub values are only unique per issuer, so a new issuer makes the old
	// identity mappings stale.
	issuerChanged := false
	if prev, err := s.cfg.IAM.GetSSOProvider(ctx, req.GetProviderId()); err == nil {
		issuerChanged = prev.OIDC.IssuerURL != req.GetIssuerUrl()
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
	if err != nil {
		return nil, err
	}
	if issuerChanged {
		// Don't fail the saved update, but be loud: stale identities stay
		// valid until this is retried.
		if _, err := s.cfg.IAM.PurgeProviderIdentities(ctx, req.GetProviderId()); err != nil {
			slog.Error("purging identities after issuer change failed", "error", err, "provider", req.GetProviderId())
		}
	}
	return &nokkuv1.PutSSOProviderResponse{Provider: providerToProto(stored)}, nil
}

func (s *sSOService) DeleteSSOProvider(
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
