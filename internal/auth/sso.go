package auth

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml/samlsp"
	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/oauth2"
	"github.com/mizuchilabs/kagi/oidc"
	"github.com/mizuchilabs/kagi/saml"
	"golang.org/x/oauth2/github"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
)

// SSOConfig carries the static (non-database) SSO provider credentials.
type SSOConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string
	// RedirectBase is the public base URL, used to build redirect URLs.
	RedirectBase string
}

// Resolvers bundles the SSO resolution hooks the kagi OIDC, OAuth2, and SAML
// handlers consume via their Options. nokku's users and credentials are
// global, so every hook ignores the tenant argument; the provider id doubles
// as the workspace id for enterprise providers and is "google" or "github"
// for the static social providers.
type Resolvers struct {
	ResolveOIDCProvider   func(ctx context.Context, t kagi.TenantID, providerID string) (*oidc.ProviderConfig, error)
	ResolveOIDCUser       func(ctx context.Context, t kagi.TenantID, id *oidc.Identity) (*kagi.User, error)
	ResolveOAuth2Provider func(ctx context.Context, t kagi.TenantID, providerID string) (*oauth2.ProviderConfig, error)
	ResolveOAuth2User     func(ctx context.Context, t kagi.TenantID, id *oauth2.Identity) (*kagi.User, error)
	ResolveSAMLIdP        func(ctx context.Context, t kagi.TenantID, providerID string) (*saml.IDPConfig, error)
	ResolveSAMLUser       func(ctx context.Context, t kagi.TenantID, id *saml.Identity) (*kagi.User, error)
}

// NewResolvers builds the SSO hooks from nokku's database and static config.
func NewResolvers(conn *db.Connection, cfg SSOConfig) Resolvers {
	return Resolvers{
		ResolveOIDCProvider:   resolveOIDCProvider(conn, cfg),
		ResolveOIDCUser:       resolveOIDCUser(conn),
		ResolveOAuth2Provider: resolveOAuth2Provider(cfg),
		ResolveOAuth2User:     resolveOAuth2User(conn),
		ResolveSAMLIdP:        resolveSAMLIdP(conn, cfg),
		ResolveSAMLUser:       resolveSAMLUser(conn),
	}
}

func resolveOIDCProvider(
	conn *db.Connection,
	cfg SSOConfig,
) func(context.Context, kagi.TenantID, string) (*oidc.ProviderConfig, error) {
	return func(ctx context.Context, _ kagi.TenantID, providerID string) (*oidc.ProviderConfig, error) {
		if providerID == "google" {
			if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" {
				return nil, kagi.ErrProviderDisabled
			}
			return &oidc.ProviderConfig{
				ProviderID:   "google",
				IssuerURL:    "https://accounts.google.com",
				ClientID:     cfg.GoogleClientID,
				ClientSecret: cfg.GoogleClientSecret,
				RedirectURL:  cfg.RedirectBase + "/oidc/callback",
				Scopes:       []string{"openid", "profile", "email"},
				EmailClaim:   "email",
				NameClaim:    "name",
			}, nil
		}

		var p *db.OidcProvider
		if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
			p, err = q.GetOIDCProviderByID(ctx, providerID)
			return err
		}); err != nil || p == nil {
			return nil, kagi.ErrProviderDisabled
		}
		issuer := strings.TrimSpace(strOr(p.IssuerURL))
		clientID := strings.TrimSpace(strOr(p.ClientID))
		if issuer == "" || clientID == "" {
			return nil, kagi.ErrProviderDisabled
		}
		return &oidc.ProviderConfig{
			ProviderID:   p.WorkspaceID,
			IssuerURL:    issuer,
			ClientID:     clientID,
			ClientSecret: string(p.ClientSecret.Bytes()),
			RedirectURL:  cfg.RedirectBase + "/oidc/callback",
			Scopes:       p.Scopes,
			DisablePKCE:  !p.UsePkce,
			EmailClaim:   p.EmailClaim,
			NameClaim:    p.NameClaim,
		}, nil
	}
}

func resolveOIDCUser(
	conn *db.Connection,
) func(context.Context, kagi.TenantID, *oidc.Identity) (*kagi.User, error) {
	return func(ctx context.Context, _ kagi.TenantID, id *oidc.Identity) (*kagi.User, error) {
		enterprise := id.ProviderID != "google"
		allowJIT := true
		if enterprise {
			var p *db.OidcProvider
			if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
				p, err = q.GetOIDCProvider(ctx, id.ProviderID)
				return err
			}); err != nil || p == nil {
				return nil, kagi.ErrIdentityRejected
			}
			allowJIT = p.AllowJitProvisioning
		}
		return resolveSSOUser(ctx, conn, id.Email, id.Name, id.ProviderID, enterprise, allowJIT)
	}
}

func resolveOAuth2Provider(
	cfg SSOConfig,
) func(context.Context, kagi.TenantID, string) (*oauth2.ProviderConfig, error) {
	return func(_ context.Context, _ kagi.TenantID, providerID string) (*oauth2.ProviderConfig, error) {
		if providerID != "github" {
			return nil, kagi.ErrProviderDisabled
		}
		if cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "" {
			return nil, kagi.ErrProviderDisabled
		}
		return &oauth2.ProviderConfig{
			ProviderID:         "github",
			ClientID:           cfg.GitHubClientID,
			ClientSecret:       cfg.GitHubClientSecret,
			AuthURL:            github.Endpoint.AuthURL,
			TokenURL:           github.Endpoint.TokenURL,
			UserInfoURL:        "https://api.github.com/user",
			EmailURL:           "https://api.github.com/user/emails",
			RedirectURL:        cfg.RedirectBase + "/oauth/callback",
			Scopes:             []string{"user:email", "read:user"},
			IDClaim:            "id",
			EmailClaim:         "email",
			EmailVerifiedClaim: "verified",
			NameClaim:          "name",
		}, nil
	}
}

func resolveOAuth2User(
	conn *db.Connection,
) func(context.Context, kagi.TenantID, *oauth2.Identity) (*kagi.User, error) {
	return func(ctx context.Context, _ kagi.TenantID, id *oauth2.Identity) (*kagi.User, error) {
		if !id.EmailVerified {
			return nil, kagi.ErrIdentityRejected
		}
		return resolveSSOUser(ctx, conn, id.Email, id.Name, id.ProviderID, false, true)
	}
}

func resolveSAMLIdP(
	conn *db.Connection,
	cfg SSOConfig,
) func(context.Context, kagi.TenantID, string) (*saml.IDPConfig, error) {
	return func(ctx context.Context, _ kagi.TenantID, providerID string) (*saml.IDPConfig, error) {
		var p *db.SamlProvider
		if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
			p, err = q.GetSAMLProviderByID(ctx, providerID)
			return err
		}); err != nil || p == nil {
			return nil, kagi.ErrProviderDisabled
		}

		metaURLStr := strings.TrimSpace(strOr(p.MetadataURL))
		if metaURLStr == "" {
			return nil, kagi.ErrProviderDisabled
		}
		metaURL, err := url.Parse(metaURLStr)
		if err != nil {
			return nil, kagi.ErrProviderDisabled
		}
		ed, err := samlsp.FetchMetadata(ctx, http.DefaultClient, *metaURL)
		if err != nil {
			return nil, kagi.ErrProviderDisabled
		}
		metadataXML, err := xml.Marshal(ed)
		if err != nil {
			return nil, kagi.ErrProviderDisabled
		}

		return &saml.IDPConfig{
			ProviderID:     p.WorkspaceID,
			MetadataXML:    metadataXML,
			SPEntityID:     cfg.RedirectBase + "/saml/metadata",
			AcsURL:         cfg.RedirectBase + "/saml/acs",
			EmailAttribute: p.EmailAttribute,
			NameAttribute:  p.NameAttribute,
		}, nil
	}
}

func resolveSAMLUser(
	conn *db.Connection,
) func(context.Context, kagi.TenantID, *saml.Identity) (*kagi.User, error) {
	return func(ctx context.Context, _ kagi.TenantID, id *saml.Identity) (*kagi.User, error) {
		var p *db.SamlProvider
		if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
			p, err = q.GetSAMLProvider(ctx, id.ProviderID)
			return err
		}); err != nil || p == nil {
			return nil, kagi.ErrIdentityRejected
		}
		return resolveSSOUser(
			ctx,
			conn,
			id.Email,
			id.Name,
			id.ProviderID,
			true,
			p.AllowJitProvisioning,
		)
	}
}

// resolveSSOUser resolves (or provisions) the local user for a verified
// external identity. enterprise identities are domain-bound and become
// workspace members; social identities are subject to SSO enforcement.
func resolveSSOUser(
	ctx context.Context,
	conn *db.Connection,
	emailAddr, name, provider string,
	enterprise bool,
	allowJIT bool,
) (*kagi.User, error) {
	domain, err := email.GetDomain(emailAddr)
	if err != nil {
		return nil, kagi.ErrIdentityRejected
	}

	if enterprise {
		var owns bool
		if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
			owns, err = q.WorkspaceOwnsVerifiedDomain(ctx, &db.WorkspaceOwnsVerifiedDomainParams{
				WorkspaceID: provider,
				Domain:      domain,
			})
			return err
		}); err != nil || !owns {
			return nil, kagi.ErrIdentityRejected
		}
	} else if ssoEnforced(ctx, conn, emailAddr) {
		return nil, kagi.ErrIdentityRejected
	}

	var u *db.User
	err = conn.WithTx(ctx, func(q *db.Queries) error {
		existing, err := q.GetUserByEmail(ctx, emailAddr)
		switch {
		case err == nil:
			u = existing
			if enterprise && name != "" {
				if u, err = q.UpdateUser(
					ctx,
					&db.UpdateUserParams{UserID: u.ID, Name: &name},
				); err != nil {
					return err
				}
			}
		case errors.Is(err, pgx.ErrNoRows):
			if enterprise && !allowJIT {
				return kagi.ErrIdentityRejected
			}
			if u, err = q.CreateUser(ctx, &db.CreateUserParams{
				Name:     name,
				Username: UsernameFromEmail(emailAddr),
				Email:    emailAddr,
			}); err != nil {
				return err
			}
		default:
			return err
		}

		if err := q.VerifyUserEmail(
			ctx,
			&db.VerifyUserEmailParams{UserID: u.ID, Email: emailAddr},
		); err != nil {
			return err
		}
		if enterprise {
			if err := q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
				UserID:      u.ID,
				WorkspaceID: provider,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil || u == nil {
		return nil, kagi.ErrIdentityRejected
	}
	user := kagiUser(u)
	return &user, nil
}

func strOr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
