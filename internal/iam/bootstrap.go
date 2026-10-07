package iam

import (
	"context"
	"errors"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
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

// Bootstrap runs on a self-hosted server, inside its one workspace. It
// seeds the providers from the environment and makes sure the admin can
// get in: an owner without a passkey or linked identity gets a sign-in
// link, returned for the host to show, at every boot until one exists.
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
		// The tenant-wide endpoints issue tokens whose iss names the tenant,
		// which OIDC discovery cannot verify.
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
	err = s.inWorkspace(ctx, func(q *db.Queries, wsID string) (err error) {
		owner, err = q.GetOwner(ctx, wsID)
		if errors.Is(err, pgx.ErrNoRows) {
			owner, err = s.createUser(ctx, q, db.CreateUserWithIDParams{
				WorkspaceID: wsID,
				Email:       cfg.AdminEmail,
				Name:        cfg.AdminName,
				Role:        string(db.RoleOwner),
			}, "")
		}
		return err
	})
	if err != nil {
		return "", err
	}
	var creds []*db.Credential
	if err := s.inWorkspace(ctx, func(q *db.Queries, wsID string) (err error) {
		creds, err = q.ListUserCredentials(ctx, &db.ListUserCredentialsParams{WorkspaceID: wsID, UserID: owner.ID})
		return err
	}); err != nil {
		return "", err
	}
	for _, c := range creds {
		if c.Type == string(MethodPasskey) || c.Type == string(MethodOIDC) {
			return "", nil
		}
	}
	return s.IssueBootstrapLink(ctx, owner)
}

// AdminLink issues a 24 hour sign-in link for the owner of ws, the way back
// in when every passkey is gone. It replaces earlier links.
func (s *Service) AdminLink(ctx context.Context, ws actor.Workspace) (*db.User, string, error) {
	ctx = actor.WithWorkspace(ctx, ws)
	var owner *db.User
	err := s.inWorkspace(ctx, func(q *db.Queries, wsID string) (err error) {
		owner, err = q.GetOwner(ctx, wsID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", errors.New("iam: the workspace has no owner, set NOKKU_ADMIN_EMAIL and start the server once")
	}
	if err != nil {
		return nil, "", err
	}
	link, err := s.IssueBootstrapLink(ctx, owner)
	return owner, link, err
}
