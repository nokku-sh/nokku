package api

import (
	"context"
	"strings"

	"connectrpc.com/connect"

	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type SSOService struct {
	cfg *config.Config
}

func NewSSOService(cfg *config.Config) *SSOService {
	return &SSOService{cfg: cfg}
}

func (s *SSOService) GetOIDCProvider(
	ctx context.Context,
	req *nokkuv1.GetOIDCProviderRequest,
) (*nokkuv1.GetOIDCProviderResponse, error) {
	var result *db.OidcProvider
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetOIDCProvider(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if result == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.GetOIDCProviderResponse{
		OidcProvider: result.ToProto(),
	}, nil
}

func (s *SSOService) UpdateOIDCProvider(
	ctx context.Context,
	req *nokkuv1.UpdateOIDCProviderRequest,
) (*nokkuv1.UpdateOIDCProviderResponse, error) {
	params := &db.UpdateOIDCProviderParams{
		WorkspaceID:          req.GetWorkspaceId(),
		Name:                 req.Name,
		IssuerURL:            req.IssuerUrl,
		ClientID:             req.ClientId,
		Scopes:               req.GetScopes(),
		EmailClaim:           req.EmailClaim,
		NameClaim:            req.NameClaim,
		UsernameClaim:        req.UsernameClaim,
		PictureClaim:         req.PictureClaim,
		IsActive:             req.IsActive,
		EnforceSso:           req.EnforceSso,
		AllowJitProvisioning: req.AllowJitProvisioning,
		UsePkce:              req.UsePkce,
	}

	if req.ClientSecret != nil {
		params.ClientSecret = crypto.EncryptedBytes(req.GetClientSecret())
	}

	if req.GetIsActive() || req.GetEnforceSso() {
		var count int32
		if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			count, err = q.CountVerifiedWorkspaceDomains(ctx, req.GetWorkspaceId())
			return err
		}); err != nil {
			return nil, DBError(err)
		}

		if count == 0 {
			return nil, NewError(
				connect.CodeFailedPrecondition,
				"cannot activate provider without a verified domain",
			)
		}
	}
	if req.GetEnforceSso() && !req.GetIsActive() {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"cannot enforce SSO without being active",
		)
	}
	if req.GetEnforceSso() {
		if !s.cfg.Billing.Has(ctx, req.GetWorkspaceId(), billing.FeatureEnforceSSO) {
			return nil, NewError(
				connect.CodeFailedPrecondition,
				"SSO enforcement requires an upgraded plan",
			)
		}
	}

	var issuerChanged bool
	var result *db.OidcProvider
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		// A changed issuer means a different IdP. Identity mappings under the
		// old issuer are stale (sub values are only unique within an issuer),
		// so they are purged after the update.
		if req.IssuerUrl != nil {
			provider, err := q.GetOIDCProvider(ctx, req.GetWorkspaceId())
			if err != nil {
				return err
			}
			if provider.IssuerURL == nil ||
				strings.TrimSpace(*provider.IssuerURL) != strings.TrimSpace(req.GetIssuerUrl()) {
				issuerChanged = true
			}
		}

		result, err = q.UpdateOIDCProvider(ctx, params)
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if result == nil {
		return nil, ErrNotFound
	}
	if issuerChanged {
		_ = s.cfg.Auth.DeleteProviderCredentials(
			ctx,
			req.GetWorkspaceId(),
			kagi.CredentialOIDC,
		)
	}

	return &nokkuv1.UpdateOIDCProviderResponse{
		OidcProvider: result.ToProto(),
	}, nil
}

func (s *SSOService) GetSAMLProvider(
	ctx context.Context,
	req *nokkuv1.GetSAMLProviderRequest,
) (*nokkuv1.GetSAMLProviderResponse, error) {
	var result *db.SamlProvider
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetSAMLProvider(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if result == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.GetSAMLProviderResponse{
		SamlProvider: result.ToProto(),
	}, nil
}

func (s *SSOService) UpdateSAMLProvider(
	ctx context.Context,
	req *nokkuv1.UpdateSAMLProviderRequest,
) (*nokkuv1.UpdateSAMLProviderResponse, error) {
	if (req.GetIsActive() || req.GetEnforceSso()) &&
		!s.cfg.Billing.Has(ctx, req.GetWorkspaceId(), billing.FeatureSAML) {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"SAML requires an Enterprise plan",
		)
	}

	params := &db.UpdateSAMLProviderParams{
		WorkspaceID:          req.GetWorkspaceId(),
		Name:                 req.Name,
		MetadataURL:          req.MetadataUrl,
		EmailAttribute:       req.EmailAttribute,
		NameAttribute:        req.NameAttribute,
		UsernameAttribute:    req.UsernameAttribute,
		PictureAttribute:     req.PictureAttribute,
		IsActive:             req.IsActive,
		EnforceSso:           req.EnforceSso,
		AllowJitProvisioning: req.AllowJitProvisioning,
	}

	if req.GetIsActive() || req.GetEnforceSso() {
		var count int32
		if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			count, err = q.CountVerifiedWorkspaceDomains(ctx, req.GetWorkspaceId())
			return err
		}); err != nil {
			return nil, DBError(err)
		}

		if count == 0 {
			return nil, NewError(
				connect.CodeFailedPrecondition,
				"cannot activate provider without a verified domain",
			)
		}
	}
	if req.GetEnforceSso() && !req.GetIsActive() {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"cannot enforce SSO without being active",
		)
	}
	if req.GetEnforceSso() {
		if !s.cfg.Billing.Has(ctx, req.GetWorkspaceId(), billing.FeatureEnforceSSO) {
			return nil, NewError(
				connect.CodeFailedPrecondition,
				"SSO enforcement requires an upgraded plan",
			)
		}
	}

	var result *db.SamlProvider
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.UpdateSAMLProvider(ctx, params)
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if result == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.UpdateSAMLProviderResponse{
		SamlProvider: result.ToProto(),
	}, nil
}

func (s *SSOService) CheckSSO(
	ctx context.Context,
	req *nokkuv1.CheckSSORequest,
) (*nokkuv1.CheckSSOResponse, error) {
	domain, err := email.GetDomain(req.GetEmail())
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid email address")
	}

	// Pre-authentication lookup by public domain: runs as a system
	// transaction, same as the other unauthenticated SSO probes.
	var oidc *db.OidcProvider
	var saml *db.SamlProvider
	_ = s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		if o, err := q.GetOIDCProviderByDomain(ctx, domain); err == nil {
			oidc = o
		}
		if sp, err := q.GetSAMLProviderByDomain(ctx, domain); err == nil {
			saml = sp
		}
		return nil
	})

	var providers []*nokkuv1.SSOProvider

	if oidc != nil && oidc.WorkspaceID != "" {
		providers = append(providers, &nokkuv1.SSOProvider{
			Type: nokkuv1.SSOProvider_TYPE_OIDC.Enum(),
			Id:   &oidc.WorkspaceID,
			Name: &oidc.Name,
		})
	}

	if saml != nil && saml.WorkspaceID != "" {
		providers = append(providers, &nokkuv1.SSOProvider{
			Type: nokkuv1.SSOProvider_TYPE_SAML.Enum(),
			Id:   &saml.WorkspaceID,
			Name: &saml.Name,
		})
	}

	hasSSO := len(providers) > 0

	var enforce bool
	if oidc != nil && oidc.EnforceSso {
		enforce = true
	}
	if saml != nil && saml.EnforceSso {
		enforce = true
	}

	return &nokkuv1.CheckSSOResponse{
		HasSso:     &hasSSO,
		EnforceSso: &enforce,
		Providers:  providers,
	}, nil
}

// checkSSOEnforced returns ErrSSORequired when SSO is enforced for the email's domain.
func checkSSOEnforced(ctx context.Context, cfg *config.Config, addr string) error {
	domain, err := email.GetDomain(addr)
	if err != nil {
		return ErrInternal
	}
	var enforced bool
	if err := cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		enforced, err = q.CheckDomainSSOEnforcement(ctx, domain)
		return err
	}); err != nil {
		return ErrInternal
	}
	if enforced {
		return ErrSSORequired
	}
	return nil
}
