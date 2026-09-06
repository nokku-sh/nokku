package config

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	"github.com/nokku-sh/nokku/internal/entitlement"
	"github.com/nokku-sh/nokku/internal/geo"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/recording"
	"github.com/nokku-sh/nokku/internal/storage"
	"github.com/nokku-sh/nokku/internal/util"
)

type EnvConfig struct {
	BaseURL        string `env:"NOKKU_BASE_URL"        envDefault:"http://localhost"`
	Port           string `env:"NOKKU_PORT"            envDefault:"3000"`
	Secret         string `env:"NOKKU_SECRET"`
	Debug          bool
	TrustedProxies []string `env:"NOKKU_TRUSTED_PROXIES"`
	AllowedOrigins []string `env:"NOKKU_ALLOWED_ORIGINS"`

	// OAuth configuration
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`
}

type Config struct {
	EnvConfig

	Conn         *db.Connection
	IAM          *iam.Service
	Audit        *audit.Service
	Email        *email.Service
	Pool         *daemon.Pool
	Storage      storage.Store
	Cache        cache.Cache
	Record       *recording.Service
	Billing      *billing.Service
	Entitlements *entitlement.Service
	Geo          *geo.Service
}

func New(ctx context.Context, cmd *cli.Command) (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, err
	}

	if cmd != nil {
		cfg.Debug = cmd.Bool("debug")
	}

	if err := util.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, err
	}

	// The nokku-owned identity engine (docs/adr/0001). It owns the public
	// schema's identity tables; the DB migration runs first via
	// db.NewConnection, so no store bootstrap precedes it.
	cfg.Conn, err = db.NewConnection(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Geo = geo.New()
	cfg.Cache, err = cache.New(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Pool = daemon.New(ctx, cfg.Conn)
	cfg.Email, err = email.New(cfg.FullURL(), cfg.Cache)
	if err != nil {
		return nil, err
	}

	if cfg.Secret == "" {
		return nil, fmt.Errorf("NOKKU_SECRET is required")
	}
	primary, err := crypto.NewSecretbox([]byte(cfg.Secret))
	if err != nil {
		return nil, err
	}
	if err := crypto.SetEncryptor(primary); err != nil {
		return nil, err
	}

	// KMS mode replaces the encryptor before anything can encrypt. Only the
	// DPoP nonce key keeps deriving from NOKKU_SECRET, which is stateless
	// and needs no KMS.
	if os.Getenv("KMS_URI") != "" {
		enc, err := kms.New(ctx, cfg.Conn)
		if err != nil {
			return nil, err
		}
		if err := crypto.SetEncryptor(enc); err != nil {
			return nil, err
		}
		enc.Start(ctx)
	}

	cfg.Storage, err = storage.New(ctx, cfg.FullURL())
	if err != nil {
		return nil, err
	}
	cfg.Billing, err = billing.New(cfg.Conn, cfg.FullURL())
	if err != nil {
		return nil, err
	}

	mode := entitlement.ModeSelfHosted
	if cfg.Billing.Enabled() {
		mode = entitlement.ModeSaaS
	}
	cfg.Entitlements = entitlement.NewService(
		entitlement.NewStore(cfg.Conn),
		cfg.Billing.License,
		mode,
	)

	if mode == entitlement.ModeSelfHosted && os.Getenv("KMS_URI") != "" &&
		!cfg.Billing.License.Valid() {
		return nil, fmt.Errorf("external KMS requires an Enterprise license")
	}
	cfg.Record = recording.New(ctx, cfg.Conn, cfg.Storage, cfg.Entitlements)

	cfg.Audit, err = audit.New(ctx, cfg.Conn, cfg.Entitlements)
	if err != nil {
		return nil, err
	}

	if err := crypto.InitDefaultHashers(); err != nil {
		return nil, err
	}

	cfg.IAM, err = iam.New(iam.Deps{
		Conn:             cfg.Conn,
		BaseURL:          cfg.FullURL(),
		Events:           cfg.Audit,
		Secret:           []byte(cfg.Secret),
		Cache:            cfg.Cache,
		PasskeyRPOrigins: passkeyOrigins(&cfg),
		OnSSOLogin: func(ctx context.Context, userID, workspaceID string) error {
			return cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
				// Existing members skip the seat gate
				if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
					WorkspaceID: workspaceID,
					UserID:      userID,
				}); err == nil {
					return nil
				}

				// Same seat gate as invitations and SCIM. The row lock makes
				// concurrent joins serialize before the count. Community
				// workspaces ship OIDC, so this path is reachable on capped
				// plans.
				if _, err := q.GetWorkspaceForUpdate(ctx, workspaceID); err != nil {
					return err
				}
				used, err := q.CountWorkspaceSeats(ctx, workspaceID)
				if err != nil {
					return err
				}
				if err := cfg.Entitlements.CanInvite(ctx, workspaceID, used); err != nil {
					return err
				}
				return q.EnsureWorkspaceMember(ctx, &db.EnsureWorkspaceMemberParams{
					UserID:      userID,
					WorkspaceID: workspaceID,
				})
			})
		},
		CanJoin: cfg.Entitlements.CanInvite,
	})
	if err != nil {
		return nil, err
	}
	if err := cfg.seedSocialProviders(ctx); err != nil {
		return nil, err
	}

	if err := cfg.BootstrapAdmin(ctx); err != nil {
		return nil, err
	}

	cfg.startBackgroundJobs(ctx)
	return &cfg, nil
}

func (c *Config) AppURL() *url.URL {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return &url.URL{}
	}
	return u
}

func (c *Config) FullURL() string {
	u := c.AppURL()

	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}

	host := u.Host
	if host == "" {
		host = "localhost"
	}

	// Append the port only when it isn't already the scheme's default, so
	// https://host:443 stays canonical.
	if _, _, err := net.SplitHostPort(host); err != nil {
		if port := c.Port; port != "" && port != defaultPort(scheme) {
			host = net.JoinHostPort(host, port)
		}
	}

	return scheme + "://" + host
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// WSOrigins returns the origin patterns allowed to open websocket
// connections: the app URL itself plus any configured extra origins (e.g.
// a frontend dev server on a different port).
func (c *Config) WSOrigins() []string {
	origins := make([]string, 0, len(c.AllowedOrigins)+1)
	origins = append(origins, c.FullURL())
	return append(origins, c.AllowedOrigins...)
}

// passkeyOrigins returns every origin the browser may assert during a
// WebAuthn ceremony: the app URL plus the frontend dev server in debug mode.
func passkeyOrigins(c *Config) []string {
	origins := []string{c.FullURL()}
	if c.Debug {
		origins = append(origins, "http://localhost:5173")
	}
	return origins
}

// seedSocialProviders seeds the static social login providers from the
// environment credentials into sso storage.
func (c *Config) seedSocialProviders(ctx context.Context) error {
	seed := func(providerID, name, clientID, clientSecret string) error {
		if clientID == "" || clientSecret == "" {
			return nil
		}
		var p iam.SSOProvider
		switch providerID {
		case "google":
			p = iam.SSOProvider{
				ProviderID: providerID,
				Method:     iam.MethodOIDC,
				Name:       name,
				Enabled:    true,
				OIDC: &iam.OIDCProvider{
					IssuerURL:       "https://accounts.google.com",
					ClientID:        clientID,
					ClientSecret:    clientSecret,
					JITProvisioning: true,
				},
			}
		case "github":
			p = iam.SSOProvider{
				ProviderID: providerID,
				Method:     iam.MethodOAuth2,
				Name:       name,
				Enabled:    true,
				OAuth2: &iam.OAuth2Provider{ //nolint:gosec // the secret comes from the environment, not hardcoded
					ClientID:        clientID,
					ClientSecret:    clientSecret,
					AuthURL:         "https://github.com/login/oauth/authorize",
					TokenURL:        "https://github.com/login/oauth/access_token",
					UserInfoURL:     "https://api.github.com/user",
					EmailURL:        "https://api.github.com/user/emails",
					Scopes:          []string{"read:user", "user:email"},
					JITProvisioning: true,
				},
			}
		}
		return c.IAM.PutSSOProvider(ctx, p)
	}
	if err := seed("google", "Google", c.GoogleClientID, c.GoogleClientSecret); err != nil {
		return err
	}
	return seed("github", "GitHub", c.GitHubClientID, c.GitHubClientSecret)
}
