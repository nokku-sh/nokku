package config

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/caarlos0/env/v11"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	"github.com/nokku-sh/nokku/internal/entitlement"
	"github.com/nokku-sh/nokku/internal/geo"
	"github.com/nokku-sh/nokku/internal/license"
	"github.com/nokku-sh/nokku/internal/storage"
	"github.com/nokku-sh/nokku/internal/util"
)

type EnvConfig struct {
	BaseURL        string `env:"NOKKU_BASE_URL"        envDefault:"http://localhost"`
	Port           string `env:"NOKKU_PORT"            envDefault:"3000"`
	Secret         string `env:"NOKKU_SECRET"`
	Debug          bool
	TrustedProxies []string `env:"NOKKU_TRUSTED_PROXIES"`

	// OAuth configuration
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`
}

type Config struct {
	EnvConfig

	Conn         *db.Connection
	Authn        *authn.Service
	Audit        *audit.Service
	Email        *email.Service
	Pool         *daemon.Pool
	Storage      storage.Store
	Cache        cache.Cache
	Entitlements *entitlement.Service
	Billing      billing.Provider
	License      *license.Key
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

	cfg.Conn, err = db.NewConnection(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Geo = geo.New()
	cfg.Cache = cache.NewMemory()
	cfg.Pool = daemon.New(ctx, cfg.Conn)
	cfg.Authn, err = authn.New(cfg.Conn)
	if err != nil {
		return nil, err
	}
	cfg.Storage, err = storage.New(ctx, cfg.FullURL())
	if err != nil {
		return nil, err
	}
	cfg.Email, err = email.New(cfg.FullURL(), cfg.Cache)
	if err != nil {
		return nil, err
	}
	cfg.Billing, err = billing.NewStripe(cfg.Conn, cfg.FullURL())
	if err != nil {
		return nil, err
	}
	cfg.License, err = license.New()
	if err != nil {
		return nil, err
	}
	cfg.Entitlements = entitlement.New(cfg.Conn.Q, cfg.License)

	cfg.Audit, err = audit.New(ctx, cfg.Conn, cfg.Entitlements)
	if err != nil {
		return nil, err
	}

	if err := crypto.InitDefaultHashers(); err != nil {
		return nil, err
	}

	if cfg.Secret != "" {
		primary, err := crypto.NewSecretbox([]byte(cfg.Secret))
		if err != nil {
			return nil, err
		}
		if err := crypto.SetEncryptor(primary); err != nil {
			return nil, err
		}
	} else {
		enc, err := kms.New(ctx, cfg.Conn)
		if err != nil {
			return nil, err
		}
		if err := crypto.SetEncryptor(enc); err != nil {
			return nil, err
		}
		enc.Start(ctx)
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
	if u.Host == "" {
		return fmt.Sprintf("http://localhost:%s", c.Port)
	}
	if _, _, err := net.SplitHostPort(u.Host); err == nil {
		return c.BaseURL
	}
	if c.Debug {
		return fmt.Sprintf("%s://%s:%s", u.Scheme, u.Host, c.Port)
	}
	return c.BaseURL
}

func (c *Config) Hostname() string {
	return c.AppURL().Hostname()
}
