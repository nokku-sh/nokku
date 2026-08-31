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
	"github.com/nokku-sh/nokku/internal/geo"
	"github.com/nokku-sh/nokku/internal/iam"
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

	Conn    *db.Connection
	IAM     *iam.Service
	Audit   *audit.Service
	Email   *email.Service
	Pool    *daemon.Pool
	Storage storage.Store
	Cache   cache.Cache
	Billing *billing.Service
	License *billing.Key
	Geo     *geo.Service
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
	// NOKKU_SECRET keys the default at-rest encryption: nokku's secretbox
	// for CA private keys and recordings, and iam derives its DPoP nonce key
	// DPoP nonce key from it. Set KMS_URI to route encryption through an
	// external KMS instead (Enterprise): a tink keyset of data keys
	// wrapped by the KMS, persisted in the database.
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
	provider, err := billing.NewStripe(cfg.Conn, cfg.FullURL())
	if err != nil {
		return nil, err
	}
	cfg.License, err = billing.NewLicense()
	if err != nil {
		return nil, err
	}

	mode := billing.ModeSelfHosted
	if provider != nil {
		mode = billing.ModeSaaS
	}
	cfg.Billing = billing.NewService(cfg.Conn, cfg.License, provider, mode)

	if mode == billing.ModeSelfHosted && os.Getenv("KMS_URI") != "" && !cfg.License.Valid() {
		return nil, fmt.Errorf("external KMS requires an Enterprise license")
	}

	cfg.Audit, err = audit.New(ctx, cfg.Conn, cfg.Billing, iamUserDirectory{cfg: &cfg})
	if err != nil {
		return nil, err
	}

	if err := crypto.InitDefaultHashers(); err != nil {
		return nil, err
	}

	cfg.IAM, err = iam.New(iam.Deps{
		Querier:          cfg.Conn.Q,
		BaseURL:          cfg.FullURL(),
		Events:           cfg.Audit,
		Secret:           []byte(cfg.Secret),
		Conn:             cfg.Conn,
		Cache:            cfg.Cache,
		PasskeyRPOrigins: passkeyOrigins(&cfg),
		OnSSOLogin: func(ctx context.Context, userID, workspaceID string) error {
			return cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
				return q.EnsureWorkspaceMember(ctx, &db.EnsureWorkspaceMemberParams{
					UserID:      userID,
					WorkspaceID: workspaceID,
				})
			})
		},
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

// iamUserDirectory adapts iam to audit's UserDirectory: it resolves an
// actor id to its user. nokku's users are global. It reads cfg.IAM at call
// time because audit is constructed before iam (iam consumes the audit
// sink), so the service pointer only becomes valid once boot completes.
type iamUserDirectory struct {
	cfg *Config
}

func (d iamUserDirectory) GetUser(ctx context.Context, userID string) (iam.User, error) {
	return d.cfg.IAM.GetUser(ctx, userID)
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
