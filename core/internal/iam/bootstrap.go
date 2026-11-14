package iam

import (
	"context"
	"errors"
	"strings"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type bootstrapConfig struct {
	AdminEmail            string `env:"NOKKU_ADMIN_EMAIL"`
	AdminName             string `env:"NOKKU_ADMIN_NAME"`
	GoogleClientID        string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret    string `env:"GOOGLE_CLIENT_SECRET"`
	MicrosoftClientID     string `env:"MICROSOFT_CLIENT_ID"`
	MicrosoftClientSecret string `env:"MICROSOFT_CLIENT_SECRET"`
	MicrosoftTenantID     string `env:"MICROSOFT_TENANT_ID"`
}

// Bootstrap reports whether the owner has no way in yet, see nokku recover.
func (s *Service) Bootstrap(ctx context.Context, ws actor.Workspace) (bool, error) {
	cfg, err := env.ParseAs[bootstrapConfig]()
	if err != nil {
		return false, err
	}
	ctx = actor.WithWorkspace(ctx, ws)

	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		// Any Google account can sign in here, so JIT starts off.
		if err := s.seedProvider(ctx, SSOProvider{
			ProviderID: "google",
			Name:       "Google",
			Enabled:    true,
			OIDC: OIDCProvider{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     cfg.GoogleClientID,
				ClientSecret: cfg.GoogleClientSecret,
			},
		}); err != nil {
			return false, err
		}
	}
	if cfg.MicrosoftClientID != "" && cfg.MicrosoftClientSecret != "" {
		// Tenant-wide iss names the tenant, which OIDC discovery cannot verify.
		tenant := strings.ToLower(cfg.MicrosoftTenantID)
		if tenant == "" || tenant == "common" || tenant == "organizations" || tenant == "consumers" {
			return false, errors.New("iam: MICROSOFT_TENANT_ID must be a tenant id")
		}
		if err := s.seedProvider(ctx, SSOProvider{
			ProviderID: "microsoft",
			Name:       "Microsoft",
			Enabled:    true,
			OIDC: OIDCProvider{
				IssuerURL:       "https://login.microsoftonline.com/" + tenant + "/v2.0",
				ClientID:        cfg.MicrosoftClientID,
				ClientSecret:    cfg.MicrosoftClientSecret,
				JITProvisioning: true,
				// Entra sends no email_verified, the pinned tenant vouches.
				TrustUnverifiedEmail: true,
			},
		}); err != nil {
			return false, err
		}
	}

	if cfg.AdminEmail == "" {
		return false, nil
	}
	if cfg.AdminName == "" {
		cfg.AdminName = strings.Split(cfg.AdminEmail, "@")[0]
	}
	var owner *db.User
	if err = s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		owner, err = q.GetOwner(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			owner, err = s.createUser(ctx, q, db.CreateUserWithIDParams{
				Email: cfg.AdminEmail,
				Name:  cfg.AdminName,
				Role:  nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER,
			})
		}
		return err
	}); err != nil {
		return false, err
	}
	creds, err := s.conn.Tenant().ListUserCredentials(ctx, owner.ID)
	if err != nil {
		return false, err
	}
	return len(creds) == 0, nil
}

// seedProvider keeps what an admin set on a stored provider.
func (s *Service) seedProvider(ctx context.Context, p SSOProvider) error {
	prev, err := s.GetSSOProvider(ctx, p.ProviderID)
	switch {
	case err == nil:
		prev.OIDC.IssuerURL = p.OIDC.IssuerURL
		prev.OIDC.ClientID = p.OIDC.ClientID
		prev.OIDC.ClientSecret = p.OIDC.ClientSecret
		p = *prev
	case !errors.Is(err, ErrNotFound):
		return err
	}
	_, err = s.PutSSOProvider(ctx, p)
	return err
}

// OwnerLink is the way back in for an owner who lost every passkey.
func (s *Service) OwnerLink(ctx context.Context, ws actor.Workspace) (*db.User, string, error) {
	ctx = actor.WithWorkspace(ctx, ws)
	owner, err := s.conn.Tenant().GetOwner(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", errors.New("iam: the workspace has no owner, set NOKKU_ADMIN_EMAIL and start the server once")
	}
	if err != nil {
		return nil, "", err
	}
	link, err := s.IssueBootstrapLink(ctx, owner)
	return owner, link, err
}
