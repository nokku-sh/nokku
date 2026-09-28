package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
)

// SSOService keeps at most one provider per workspace. The provider id is the
// workspace id, so saving the other protocol overwrites it.
type SSOService struct {
	cfg *config.Config
}

func NewSSOService(cfg *config.Config) *SSOService {
	return &SSOService{cfg: cfg}
}

// requireVerifiedDomain gates SSO and SCIM. SSO without a verified domain
// never matches a login, SCIM without one could squat arbitrary emails.
func requireVerifiedDomain(
	ctx context.Context,
	svc *iam.Service,
	what, workspaceID string,
) error {
	domains, err := svc.ListTenantDomains(ctx, workspaceID)
	if err != nil {
		return DBError(err)
	}
	for _, d := range domains {
		if d.Verified() {
			return nil
		}
	}
	return NewError(
		connect.CodeFailedPrecondition,
		"Add and verify a domain before configuring "+what,
	)
}

func (s *SSOService) GetSSOProvider(
	ctx context.Context,
	req *nokkuv1.GetSSOProviderRequest,
) (*nokkuv1.GetSSOProviderResponse, error) {
	p, err := s.cfg.IAM.GetWorkspaceSSOProvider(ctx, req.GetWorkspaceId())
	if errors.Is(err, iam.ErrNotFound) {
		return &nokkuv1.GetSSOProviderResponse{}, nil
	}
	if err != nil {
		return nil, ssoError(err)
	}
	return &nokkuv1.GetSSOProviderResponse{Provider: providerToProto(p)}, nil
}

func (s *SSOService) UpdateSSOProvider(
	ctx context.Context,
	req *nokkuv1.UpdateSSOProviderRequest,
) (*nokkuv1.UpdateSSOProviderResponse, error) {
	p := iam.SSOProvider{
		WorkspaceID: req.GetWorkspaceId(),
		ProviderID:  req.GetWorkspaceId(),
		Name:        req.GetName(),
		Enabled:     req.GetIsActive(),
	}
	prev, _ := s.cfg.IAM.GetWorkspaceSSOProvider(ctx, req.GetWorkspaceId())

	issuerChanged := false
	switch req.GetMethod() {
	case "oidc":
		p.Method = iam.MethodOIDC
		// An empty secret keeps the stored one.
		p.OIDC = &iam.OIDCProvider{
			IssuerURL:       req.GetConfig().GetIssuerUrl(),
			ClientID:        req.GetConfig().GetClientId(),
			ClientSecret:    req.GetClientSecret(),
			Scopes:          req.GetConfig().GetScopes(),
			JITProvisioning: req.GetAllowJitProvisioning(),
			EnforceSSO:      req.GetEnforceSso(),
		}
		// sub values are only unique per issuer, so a new issuer makes the
		// old identity mappings stale.
		issuerChanged = prev != nil && prev.OIDC != nil && prev.OIDC.IssuerURL != p.OIDC.IssuerURL
	case "saml":
		p.Method = iam.MethodSAML
		p.SAML = &iam.SAMLIDP{
			MetadataURL:     req.GetConfig().GetMetadataUrl(),
			JITProvisioning: req.GetAllowJitProvisioning(),
			EnforceSSO:      req.GetEnforceSso(),
		}
		// No metadata keeps the stored one, so toggling flags never wipes it.
		if p.SAML.MetadataURL == "" && prev != nil && prev.SAML != nil {
			p.SAML.MetadataURL = prev.SAML.MetadataURL
			p.SAML.MetadataXML = prev.SAML.MetadataXML
		}
	default:
		return nil, NewError(connect.CodeInvalidArgument, "method must be oidc or saml")
	}

	if err := requireVerifiedDomain(ctx, s.cfg.IAM, "an SSO provider", req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	if err := s.cfg.IAM.PutSSOProvider(ctx, p); err != nil {
		return nil, ssoError(err)
	}
	if issuerChanged {
		// Don't fail the saved update, but be loud: stale identities stay
		// valid until this is retried.
		if _, err := s.cfg.IAM.PurgeProviderIdentities(ctx, iam.MethodOIDC, req.GetWorkspaceId()); err != nil {
			slog.Error(
				"purging identities after issuer change failed",
				"error", err,
				"workspace_id", req.GetWorkspaceId(),
			)
		}
	}

	stored, err := s.cfg.IAM.GetWorkspaceSSOProvider(ctx, req.GetWorkspaceId())
	if err != nil {
		return nil, ssoError(err)
	}
	return &nokkuv1.UpdateSSOProviderResponse{Provider: providerToProto(stored)}, nil
}

func ssoError(err error) error {
	if errors.Is(err, iam.ErrNotFound) {
		return ErrNotFound
	}
	return DBError(err)
}

func providerToProto(p *iam.SSOProvider) *nokkuv1.SSOProvider {
	out := &nokkuv1.SSOProvider{
		WorkspaceId: &p.WorkspaceID,
		Method:      new(string(p.Method)),
		Name:        &p.Name,
		IsActive:    &p.Enabled,
		CreatedAt:   db.SafeTimestamp(&p.CreatedAt),
		UpdatedAt:   db.SafeTimestamp(&p.UpdatedAt),
	}
	cfg := &nokkuv1.SSOConfig{}
	switch {
	case p.OIDC != nil:
		out.EnforceSso = new(p.OIDC.EnforceSSO)
		out.AllowJitProvisioning = new(p.OIDC.JITProvisioning)
		cfg.IssuerUrl = &p.OIDC.IssuerURL
		cfg.ClientId = &p.OIDC.ClientID
		cfg.Scopes = p.OIDC.Scopes
	case p.SAML != nil:
		out.EnforceSso = new(p.SAML.EnforceSSO)
		out.AllowJitProvisioning = new(p.SAML.JITProvisioning)
		cfg.MetadataUrl = &p.SAML.MetadataURL
	default:
		return out
	}
	out.Config = cfg
	return out
}
