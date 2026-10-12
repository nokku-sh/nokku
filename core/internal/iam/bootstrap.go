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

// Bootstrap seeds the providers from the environment. An owner with no way in gets a sign-in link at every boot.
func (s *Service) Bootstrap(ctx context.Context, ws actor.Workspace) (string, error) {
	cfg, err := env.ParseAs[bootstrapConfig]()
	if err != nil {
		return "", err
	}
	ctx = actor.WithWorkspace(ctx, ws)

	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		if _, err := s.PutSSOProvider(ctx, SSOProvider{
			ProviderID: "google",
			Name:       "Google",
			Enabled:    true,
			OIDC: OIDCProvider{
				IssuerURL:       "https://accounts.google.com",
				ClientID:        cfg.GoogleClientID,
				ClientSecret:    cfg.GoogleClientSecret,
				JITProvisioning: true,
			},
		}); err != nil {
			return "", err
		}
	}
	if cfg.MicrosoftClientID != "" && cfg.MicrosoftClientSecret != "" {
		// The tenant-wide endpoints issue tokens whose iss names the tenant, which OIDC discovery cannot verify.
		tenant := strings.ToLower(cfg.MicrosoftTenantID)
		if tenant == "" || tenant == "common" || tenant == "organizations" || tenant == "consumers" {
			return "", errors.New("iam: MICROSOFT_TENANT_ID must be a tenant id")
		}
		if _, err := s.PutSSOProvider(ctx, SSOProvider{
			ProviderID: "microsoft",
			Name:       "Microsoft",
			Enabled:    true,
			OIDC: OIDCProvider{
				IssuerURL:       "https://login.microsoftonline.com/" + tenant + "/v2.0",
				ClientID:        cfg.MicrosoftClientID,
				ClientSecret:    cfg.MicrosoftClientSecret,
				JITProvisioning: true,
			},
		}); err != nil {
			return "", err
		}
	}

	if cfg.AdminEmail == "" {
		return "", nil
	}
	var owner *db.User
	err = s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		owner, err = q.GetOwner(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			owner, err = s.createUser(ctx, q, db.CreateUserWithIDParams{
				Email: cfg.AdminEmail,
				Name:  cfg.AdminName,
				Role:  nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER,
			}, "")
		}
		return err
	})
	if err != nil {
		return "", err
	}
	creds, err := s.conn.Tenant().ListUserCredentials(ctx, owner.ID)
	if err != nil {
		return "", err
	}
	if len(creds) > 0 {
		return "", nil
	}
	return s.IssueBootstrapLink(ctx, owner)
}

// AdminLink issues a 24 hour sign-in link for the owner, the way back in when every passkey is gone.
func (s *Service) AdminLink(ctx context.Context, ws actor.Workspace) (*db.User, string, error) {
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
