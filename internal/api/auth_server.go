package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/mizuchilabs/kagi"
	kagidevice "github.com/mizuchilabs/kagi/deviceauth"
	kagioauth "github.com/mizuchilabs/kagi/oauth2"
	kagioidc "github.com/mizuchilabs/kagi/oidc"
	kagisaml "github.com/mizuchilabs/kagi/saml"
	"github.com/mizuchilabs/kagi/server"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
)

// deviceSessionTTL is how long an nk device session lasts before the user
// must re-run the browser device flow. Longer than the web session (24h) so a
// daily-driver CLI is not hitting the browser every day, but bounded because
// there is no refresh flow.
const deviceSessionTTL = 7 * 24 * time.Hour

// NewAuthHandler builds the consolidated kagi auth server for nokku: the SSO
// redirect flows, passkey ceremonies, device flow, and the password/backup-
// code/email flows, all mounted under their existing paths.
//
// Business rules live in three places: account state and SSO enforcement are
// enforced centrally by the kagi service (see auth.NewService), SSO
// enforcement at register/signup is the BeforeRegister hook and the passkey
// signup resolver, and email delivery is the mailer adapter.
func NewAuthHandler(cfg *config.Config) (*server.Handler, error) {
	return server.New(cfg.Auth.Kagi, server.Options{
		Cache:   cfg.Cache,
		BaseURL: cfg.FullURL(),

		Flows: &server.Flows{
			ValidateEmail: email.Verify,
			BeforeRegister: func(ctx context.Context, addr string) error {
				if err := checkSSOEnforced(ctx, cfg, addr); err != nil {
					return kagi.ErrSSORequired
				}
				return nil
			},
			Tokens: cfg.Auth.Tokens(),
			Mailer: kagiMailer{cfg: cfg},
			OnVerifyEmail: func(ctx context.Context, u kagi.User) error {
				row, err := cfg.Conn.Q.GetUserByID(ctx, u.ID)
				if err != nil {
					return err
				}
				return cfg.Conn.Q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
					UserID: u.ID,
					Email:  row.Email,
				})
			},
			OnPasswordReset: func(ctx context.Context, u kagi.User) error {
				return cfg.Auth.Kagi.RevokeSubjectSessions(ctx, "", u.ID)
			},
		},

		Passkeys: server.PasskeyConfig{
			Config: webauthn.Config{
				RPDisplayName: "Nokku",
				RPID:          cfg.AppURL().Hostname(),
				RPOrigins:     rpOrigins(cfg),
			},
			Secure: true,
			Login:  &server.PasskeyFlow{},
			Register: &server.PasskeyFlow{
				ResolveUser: func(ctx context.Context, _ *http.Request) (kagi.User, error) {
					p, ok := kagi.PrincipalFromContext(ctx)
					if !ok {
						return kagi.User{}, errors.New("not authenticated")
					}
					return cfg.Auth.GetUser(ctx, p.SubjectID)
				},
				SkipSessionOnRegister: true,
			},
			Signup: &server.PasskeyFlow{
				ResolveUser: func(ctx context.Context, r *http.Request) (kagi.User, error) {
					addr := r.FormValue("email")
					if addr == "" {
						return kagi.User{}, errors.New("email required")
					}
					if err := email.Verify(addr); err != nil {
						return kagi.User{}, errors.New("invalid email address")
					}
					if err := checkSSOEnforced(ctx, cfg, addr); err != nil {
						return kagi.User{}, kagi.ErrSSORequired
					}
					if u, err := cfg.Auth.GetUserByEmail(ctx, addr); err == nil {
						return u, nil
					} else if !errors.Is(err, kagi.ErrNotFound) {
						return kagi.User{}, err
					}
					name := r.FormValue("name")
					if name == "" {
						name = auth.UsernameFromEmail(addr)
					}
					return cfg.Auth.CreateUser(ctx, kagi.User{Email: addr, DisplayName: name})
				},
				SkipSessionOnRegister: true,
			},
		},

		OIDC: &kagioidc.Options{
			Cache:           cfg.Cache,
			ErrorRedirect:   cfg.FullURL() + "/auth-error",
			ResolveProvider: cfg.Auth.Resolvers.ResolveOIDCProvider,
			ResolveUser:     cfg.Auth.Resolvers.ResolveOIDCUser,
		},

		OAuth2: &kagioauth.Options{
			Cache:           cfg.Cache,
			ErrorRedirect:   cfg.FullURL() + "/auth-error",
			ResolveProvider: cfg.Auth.Resolvers.ResolveOAuth2Provider,
			ResolveUser:     cfg.Auth.Resolvers.ResolveOAuth2User,
		},

		SAML: &kagisaml.Options{
			Cache:         cfg.Cache,
			Keypair:       auth.NewSAMLSPKeyStore(cfg.Conn),
			AcsURL:        cfg.FullURL() + "/saml/acs",
			SPEntityID:    cfg.FullURL() + "/saml/metadata",
			ErrorRedirect: cfg.FullURL() + "/auth-error",
			ResolveIDP:    cfg.Auth.Resolvers.ResolveSAMLIdP,
			ResolveUser:   cfg.Auth.Resolvers.ResolveSAMLUser,
		},

		Device: &kagidevice.Options{
			Cache:           cfg.Cache,
			VerificationURI: cfg.FullURL() + "/device",
			DPoP:            cfg.Auth.DPoP(),
			Kind:            auth.ActorTypeDevice,
			SessionTTL:      deviceSessionTTL,
		},
	})
}

// rpOrigins returns the WebAuthn relying-party origins: the app URL plus the
// frontend dev server in debug mode.
func rpOrigins(cfg *config.Config) []string {
	origins := []string{cfg.FullURL()}
	if cfg.Debug {
		origins = append(origins, "http://localhost:5173")
	}
	return origins
}
