package api

import (
	"context"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

// SSOProvider configuration is stored and resolved by kagi's SSOManager;
// this service only gates it (permissions, verified domains, billing) and
// maps it to the API surface. The provider id doubles as the workspace id,
// matching the tenant the provider is stored under, so a tenant holds at
// most one provider record: configuring the other method overwrites it.
// Nothing is created by default; a workspace starts with no provider, and
// the Get RPCs report that as an empty provider rather than an error so
// the UI can render its setup form.

type SSOService struct {
	cfg *config.Config
}

func NewSSOService(cfg *config.Config) *SSOService {
	return &SSOService{cfg: cfg}
}

// requireVerifiedDomain gates provider setup on domain ownership: home
// realm discovery only routes logins whose email domain is bound to the
// workspace, so a provider without a verified domain can never match.
func (s *SSOService) requireVerifiedDomain(ctx context.Context, workspaceID string) error {
	domains, err := s.cfg.Auth.Service().Domains.List(ctx, kagi.TenantID(workspaceID))
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
		"Add and verify a domain before configuring an SSO provider",
	)
}

func (s *SSOService) GetOIDCProvider(
	ctx context.Context,
	req *nokkuv1.GetOIDCProviderRequest,
) (*nokkuv1.GetOIDCProviderResponse, error) {
	p, err := s.cfg.Auth.Service().SSO.Get(ctx, kagi.TenantID(req.GetWorkspaceId()), req.GetWorkspaceId())
	if err != nil && !kagi.IsNotFound(err) {
		return nil, ssoError(err)
	}
	// Unset, or the single slot is held by a SAML provider: report an
	// unconfigured OIDC provider instead of an error.
	if err != nil || p.OIDC == nil {
		return &nokkuv1.GetOIDCProviderResponse{
			OidcProvider: emptyOIDCProvider(req.GetWorkspaceId()),
		}, nil
	}
	return &nokkuv1.GetOIDCProviderResponse{
		OidcProvider: oidcProviderToProto(p),
	}, nil
}

func (s *SSOService) UpdateOIDCProvider(
	ctx context.Context,
	req *nokkuv1.UpdateOIDCProviderRequest,
) (*nokkuv1.UpdateOIDCProviderResponse, error) {
	// A changed issuer means a different IdP. Identity mappings under the
	// old issuer are stale (sub values are only unique within an issuer),
	// so they are purged after the update. Users and their linked
	// credentials are global in nokku, hence the empty tenant.
	issuerChanged := false
	if prev, err := s.cfg.Auth.Service().SSO.Get(
		ctx,
		kagi.TenantID(req.GetWorkspaceId()),
		req.GetWorkspaceId(),
	); err == nil && prev.OIDC != nil &&
		prev.OIDC.IssuerURL != req.GetIssuerUrl() {
		issuerChanged = true
	}

	if err := s.requireVerifiedDomain(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}

	p := kagi.SSOProvider{
		TenantID:   kagi.TenantID(req.GetWorkspaceId()),
		ProviderID: req.GetWorkspaceId(),
		Method:     kagi.MethodOIDC,
		Name:       req.GetName(),
		Enabled:    req.GetIsActive(),
		OIDC: &kagi.OIDCProvider{
			// RedirectURL stays empty: kagi derives it from BaseURL.
			IssuerURL:       req.GetIssuerUrl(),
			ClientID:        req.GetClientId(),
			ClientSecret:    req.GetClientSecret(),
			Scopes:          req.GetScopes(),
			JITProvisioning: req.GetAllowJitProvisioning(),
			EnforceSSO:      req.GetEnforceSso(),
		},
	}
	if err := s.cfg.Auth.Service().SSO.Put(ctx, p); err != nil {
		return nil, ssoError(err)
	}
	if issuerChanged {
		_, _ = s.cfg.Auth.Service().Credentials.DeleteByProvider(
			ctx,
			"",
			req.GetWorkspaceId(),
		)
	}

	stored, err := s.cfg.Auth.Service().SSO.Get(ctx, kagi.TenantID(req.GetWorkspaceId()), req.GetWorkspaceId())
	if err != nil {
		return nil, ssoError(err)
	}
	return &nokkuv1.UpdateOIDCProviderResponse{
		OidcProvider: oidcProviderToProto(stored),
	}, nil
}

func (s *SSOService) GetSAMLProvider(
	ctx context.Context,
	req *nokkuv1.GetSAMLProviderRequest,
) (*nokkuv1.GetSAMLProviderResponse, error) {
	p, err := s.cfg.Auth.Service().SSO.Get(ctx, kagi.TenantID(req.GetWorkspaceId()), req.GetWorkspaceId())
	if err != nil && !kagi.IsNotFound(err) {
		return nil, ssoError(err)
	}
	// Unset, or the single slot is held by an OIDC provider: report an
	// unconfigured SAML provider instead of an error.
	if err != nil || p.SAML == nil {
		return &nokkuv1.GetSAMLProviderResponse{
			SamlProvider: emptySAMLProvider(req.GetWorkspaceId()),
		}, nil
	}
	return &nokkuv1.GetSAMLProviderResponse{
		SamlProvider: samlProviderToProto(p),
	}, nil
}

func (s *SSOService) UpdateSAMLProvider(
	ctx context.Context,
	req *nokkuv1.UpdateSAMLProviderRequest,
) (*nokkuv1.UpdateSAMLProviderResponse, error) {
	if req.GetIsActive() && !s.cfg.Billing.Has(ctx, req.GetWorkspaceId(), billing.FeatureSAML) {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"SAML requires an Enterprise plan",
		)
	}
	if err := s.requireVerifiedDomain(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	p := kagi.SSOProvider{
		TenantID:   kagi.TenantID(req.GetWorkspaceId()),
		ProviderID: req.GetWorkspaceId(),
		Method:     kagi.MethodSAML,
		Name:       req.GetName(),
		Enabled:    req.GetIsActive(),
		SAML: &kagi.SAMLIDP{
			MetadataURL:     req.GetMetadataUrl(),
			JITProvisioning: req.GetAllowJitProvisioning(),
			EnforceSSO:      req.GetEnforceSso(),
		},
	}
	if err := s.cfg.Auth.Service().SSO.Put(ctx, p); err != nil {
		return nil, ssoError(err)
	}

	stored, err := s.cfg.Auth.Service().SSO.Get(ctx, kagi.TenantID(req.GetWorkspaceId()), req.GetWorkspaceId())
	if err != nil {
		return nil, ssoError(err)
	}
	return &nokkuv1.UpdateSAMLProviderResponse{
		SamlProvider: samlProviderToProto(stored),
	}, nil
}

func ssoError(err error) error {
	if kagi.IsNotFound(err) {
		return ErrNotFound
	}
	return DBError(err)
}

// emptyProvider marks a workspace that has no provider of the requested
// method configured yet. Only identity fields are set; the UI treats a
// missing payload (issuer URL, metadata URL) as "needs setup".
// IsActive is false rather than unset so the proto unambiguously reads as
// a disabled, unconfigured provider.

func emptyOIDCProvider(workspaceID string) *nokkuv1.OIDCProvider {
	isActive := false
	return &nokkuv1.OIDCProvider{
		WorkspaceId: &workspaceID,
		IsActive:    &isActive,
	}
}

func emptySAMLProvider(workspaceID string) *nokkuv1.SAMLProvider {
	isActive := false
	return &nokkuv1.SAMLProvider{
		WorkspaceId: &workspaceID,
		IsActive:    &isActive,
	}
}

func oidcProviderToProto(p kagi.SSOProvider) *nokkuv1.OIDCProvider {
	out := &nokkuv1.OIDCProvider{
		WorkspaceId: &p.ProviderID,
		Name:        &p.Name,
		IsActive:    &p.Enabled,
		CreatedAt:   db.SafeTimestamp(&p.CreatedAt),
		UpdatedAt:   db.SafeTimestamp(&p.UpdatedAt),
	}
	if p.OIDC != nil {
		issuerURL, clientID := p.OIDC.IssuerURL, p.OIDC.ClientID
		enforceSSO, jit := p.OIDC.EnforceSSO, p.OIDC.JITProvisioning
		out.IssuerUrl = &issuerURL
		out.ClientId = &clientID
		out.Scopes = p.OIDC.Scopes
		out.EnforceSso = &enforceSSO
		out.AllowJitProvisioning = &jit
	}
	return out
}

func samlProviderToProto(p kagi.SSOProvider) *nokkuv1.SAMLProvider {
	out := &nokkuv1.SAMLProvider{
		WorkspaceId: &p.ProviderID,
		Name:        &p.Name,
		IsActive:    &p.Enabled,
		CreatedAt:   db.SafeTimestamp(&p.CreatedAt),
		UpdatedAt:   db.SafeTimestamp(&p.UpdatedAt),
	}
	if p.SAML != nil {
		metadataURL := p.SAML.MetadataURL
		enforceSSO, jit := p.SAML.EnforceSSO, p.SAML.JITProvisioning
		out.MetadataUrl = &metadataURL
		out.EnforceSso = &enforceSSO
		out.AllowJitProvisioning = &jit
	}
	return out
}
