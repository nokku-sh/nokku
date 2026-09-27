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

// SSO provider configuration is stored by the iam SSO manager in one unified
// table (oidc/oauth2/saml discriminated by method); this service only gates
// it (permissions, verified domains, billing) and maps it to the API surface.
// The provider id doubles as the workspace id, matching the tenant the
// provider is stored under, so a workspace holds at most one provider record:
// saving the other protocol's config overwrites it. Nothing is created by
// default; a workspace starts with no provider, and the Get RPC reports that
// as an unset provider rather than an error so the UI can render its setup
// form.

type SSOService struct {
	cfg *config.Config
}

func NewSSOService(cfg *config.Config) *SSOService {
	return &SSOService{cfg: cfg}
}

// requireVerifiedDomain gates org-level setup on domain ownership: home
// realm discovery only routes logins whose email domain is bound to the
// workspace, so SSO without a verified domain can never match, and SCIM
// without one could mint accounts on arbitrary emails.
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

	issuerChanged := false
	switch req.GetMethod() {
	case "oidc":
		p.Method = iam.MethodOIDC
		p.OIDC = &iam.OIDCProvider{
			// RedirectURL stays empty: the login flow derives it from BaseURL.
			IssuerURL:       req.GetConfig().GetIssuerUrl(),
			ClientID:        req.GetConfig().GetClientId(),
			Scopes:          req.GetConfig().GetScopes(),
			JITProvisioning: req.GetAllowJitProvisioning(),
			EnforceSSO:      req.GetEnforceSso(),
		}
		if req.GetClientSecret() != "" {
			p.OIDC.ClientSecret = req.GetClientSecret()
		}
		// A changed issuer means a different IdP. Identity mappings under
		// the old issuer are stale (sub values are only unique within an
		// issuer), so they are purged after the update. Users and their
		// linked credentials are global.
		if prev, err := s.cfg.IAM.GetWorkspaceSSOProvider(ctx, req.GetWorkspaceId()); err == nil &&
			prev.OIDC != nil &&
			prev.OIDC.IssuerURL != p.OIDC.IssuerURL {
			issuerChanged = true
		}
	case "saml":
		// SAML activation is gated by the entitlement guard interceptor
		// (deactivation must always work, so the gate is conditional).
		p.Method = iam.MethodSAML
		p.SAML = &iam.SAMLIDP{
			MetadataURL:     req.GetConfig().GetMetadataUrl(),
			JITProvisioning: req.GetAllowJitProvisioning(),
			EnforceSSO:      req.GetEnforceSso(),
		}
		// An update that sends no metadata keeps the stored IdP metadata, so
		// toggling JIT provisioning or enforce-SSO never wipes a working
		// configuration (mirrors how an empty client secret is handled).
		if p.SAML.MetadataURL == "" {
			if prev, err := s.cfg.IAM.GetWorkspaceSSOProvider(
				ctx,
				req.GetWorkspaceId(),
			); err == nil &&
				prev.SAML != nil {
				p.SAML.MetadataURL = prev.SAML.MetadataURL
				p.SAML.MetadataXML = prev.SAML.MetadataXML
			}
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
		// The update itself succeeded, so a purge failure must not fail the
		// call; it must however be loud: stale identities under the old
		// issuer stay valid until this is retried.
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

// providerToProto lifts the stored provider into the API shape: shared
// settings at the top, a generic config block carrying whichever protocol
// fields are set. Enforce/JIT live in the stored config, so they come from
// whichever protocol is present.
func providerToProto(p *iam.SSOProvider) *nokkuv1.SSOProvider {
	method := string(p.Method)
	out := &nokkuv1.SSOProvider{
		WorkspaceId: &p.WorkspaceID,
		Method:      &method,
		Name:        &p.Name,
		IsActive:    &p.Enabled,
		CreatedAt:   db.SafeTimestamp(&p.CreatedAt),
		UpdatedAt:   db.SafeTimestamp(&p.UpdatedAt),
	}
	cfg := &nokkuv1.SSOConfig{}
	switch {
	case p.OIDC != nil:
		enforceSSO, jit := p.OIDC.EnforceSSO, p.OIDC.JITProvisioning
		out.EnforceSso = &enforceSSO
		out.AllowJitProvisioning = &jit
		cfg.IssuerUrl = &p.OIDC.IssuerURL
		cfg.ClientId = &p.OIDC.ClientID
		cfg.Scopes = p.OIDC.Scopes
	case p.SAML != nil:
		enforceSSO, jit := p.SAML.EnforceSSO, p.SAML.JITProvisioning
		out.EnforceSso = &enforceSSO
		out.AllowJitProvisioning = &jit
		cfg.MetadataUrl = &p.SAML.MetadataURL
	default:
		return out
	}
	out.Config = cfg
	return out
}
