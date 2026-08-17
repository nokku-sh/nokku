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

// ssoPolicy builds the kagi Policy hooks from nokku's providers. The provider
// id doubles as the workspace id for enterprise OIDC/SAML, and is "google" or
// "github" for the static social providers.
func ssoPolicy(conn *db.Connection, cfg SSOConfig) kagi.Policy {
	return kagi.Policy{
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
) func(context.Context, kagi.TenantID, string) (*kagi.OIDCProviderConfig, error) {
	return func(ctx context.Context, _ kagi.TenantID, providerID string) (*kagi.OIDCProviderConfig, error) {
		if providerID == "google" {
			return &kagi.OIDCProviderConfig{
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
		}); err != nil || p.IssuerURL == nil || p.ClientID == nil {
			return nil, kagi.ErrProviderDisabled
		}
		return &kagi.OIDCProviderConfig{
			ProviderID:   p.WorkspaceID,
			IssuerURL:    strings.TrimSpace(*p.IssuerURL),
			ClientID:     *p.ClientID,
			ClientSecret: string(p.ClientSecret.Bytes()),
			RedirectURL:  cfg.RedirectBase + "/oidc/callback",
			Scopes:       p.Scopes,
			UsePKCE:      p.UsePkce,
			EmailClaim:   p.EmailClaim,
			NameClaim:    p.NameClaim,
		}, nil
	}
}

func resolveOIDCUser(
	conn *db.Connection,
) func(context.Context, kagi.TenantID, *kagi.OIDCIdentity) (*kagi.User, error) {
	return func(ctx context.Context, _ kagi.TenantID, id *kagi.OIDCIdentity) (*kagi.User, error) {
		enterprise := id.ProviderID != "google"
		allowJIT := true
		if enterprise {
			var p *db.OidcProvider
			if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
				p, err = q.GetOIDCProvider(ctx, id.ProviderID)
				return err
			}); err != nil {
				return nil, kagi.ErrIdentityRejected
			}
			allowJIT = p.AllowJitProvisioning
		}
		return resolveSSOUser(ctx, conn, id.Email, id.Name, id.ProviderID, enterprise, allowJIT)
	}
}

func resolveOAuth2Provider(
	cfg SSOConfig,
) func(context.Context, kagi.TenantID, string) (*kagi.OAuth2ProviderConfig, error) {
	return func(_ context.Context, _ kagi.TenantID, providerID string) (*kagi.OAuth2ProviderConfig, error) {
		if providerID != "github" {
			return nil, kagi.ErrProviderDisabled
		}
		return &kagi.OAuth2ProviderConfig{
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
) func(context.Context, kagi.TenantID, *kagi.OAuth2Identity) (*kagi.User, error) {
	return func(ctx context.Context, _ kagi.TenantID, id *kagi.OAuth2Identity) (*kagi.User, error) {
		if !id.EmailVerified {
			return nil, kagi.ErrIdentityRejected
		}
		return resolveSSOUser(ctx, conn, id.Email, id.Name, id.ProviderID, false, true)
	}
}

func resolveSAMLIdP(
	conn *db.Connection,
	cfg SSOConfig,
) func(context.Context, kagi.TenantID, string) (*kagi.SAMLIdPConfig, error) {
	return func(ctx context.Context, _ kagi.TenantID, providerID string) (*kagi.SAMLIdPConfig, error) {
		var p *db.SamlProvider
		if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
			p, err = q.GetSAMLProviderByID(ctx, providerID)
			return err
		}); err != nil || p.MetadataURL == nil {
			return nil, kagi.ErrProviderDisabled
		}

		metaURL, err := url.Parse(*p.MetadataURL)
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

		return &kagi.SAMLIdPConfig{
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
) func(context.Context, kagi.TenantID, *kagi.SAMLIdentity) (*kagi.User, error) {
	return func(ctx context.Context, _ kagi.TenantID, id *kagi.SAMLIdentity) (*kagi.User, error) {
		var p *db.SamlProvider
		if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
			p, err = q.GetSAMLProvider(ctx, id.ProviderID)
			return err
		}); err != nil {
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
	return &kagi.User{ID: u.ID, Email: u.Email, DisplayName: u.Name}, nil
}
