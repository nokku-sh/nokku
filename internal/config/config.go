package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

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
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/pki"
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
}

type Config struct {
	EnvConfig

	Conn         *db.Connection
	IAM          *iam.Service
	Audit        *audit.Service
	Email        *email.Service
	Pool         *daemon.Pool
	Storage      *storage.Storage
	Cache        cache.Cache
	Record       *recording.Service
	Billing      *billing.Service
	Entitlements *entitlement.Service
}

func New(ctx context.Context, cmd *cli.Command) (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, err
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("NOKKU_SECRET is required")
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
	cfg.Cache, err = cache.New(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Pool = daemon.New(ctx, cfg.Conn)
	go cfg.Pool.Listen(ctx, cfg.Conn.Pool.Config().ConnConfig)
	cfg.Email, err = email.New(cfg.FullURL(), cfg.Cache)
	if err != nil {
		return nil, err
	}

	// KMS replaces the secretbox before anything encrypts. The DPoP nonce key
	// still derives from NOKKU_SECRET.
	usesKMS := true
	enc, err := kms.New(ctx, cfg.Conn)
	switch {
	case errors.Is(err, kms.ErrNotConfigured):
		usesKMS = false
		primary, err := crypto.NewSecretbox([]byte(cfg.Secret))
		if err != nil {
			return nil, err
		}
		if err := crypto.SetEncryptor(primary); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := crypto.SetEncryptor(enc); err != nil {
			return nil, err
		}
		enc.Start(ctx)
	}

	cfg.Storage, err = storage.New(ctx, cfg.FullURL())
	if err != nil {
		return nil, err
	}
	cfg.Billing, err = billing.New(ctx, cfg.Conn, cfg.FullURL())
	if err != nil {
		return nil, err
	}

	mode := entitlement.ModeSelfHosted
	if cfg.Billing.Enabled() {
		mode = entitlement.ModeSaaS
	}
	if mode == entitlement.ModeSelfHosted {
		cfg.Entitlements = entitlement.NewService(cfg.Conn, entitlement.EnvLicense(), mode)
		cfg.Entitlements.WatchLicense(ctx)
	} else {
		cfg.Entitlements = entitlement.NewService(cfg.Conn, nil, mode)
	}

	// An expired license still starts. The data is encrypted under the KMS
	// key, so refusing here would turn a late renewal into an outage.
	if mode == entitlement.ModeSelfHosted && usesKMS && cfg.Entitlements.License() == nil {
		return nil, fmt.Errorf("external KMS requires an Enterprise license")
	}
	cfg.Audit, err = audit.New(ctx, cfg.Conn, cfg.Entitlements)
	if err != nil {
		return nil, err
	}
	cfg.Record = recording.New(ctx, cfg.Conn, cfg.Storage, cfg.Entitlements, cfg.Audit)

	cfg.IAM, err = iam.New(ctx, iam.Deps{
		Conn:             cfg.Conn,
		BaseURL:          cfg.FullURL(),
		Events:           cfg.Audit,
		Secret:           []byte(cfg.Secret),
		Cache:            cfg.Cache,
		PasskeyRPOrigins: passkeyOrigins(&cfg),
		CanJoin:          cfg.Entitlements.CanInvite,
		StrictEmail:      mode == entitlement.ModeSaaS,
	})
	if err != nil {
		return nil, err
	}

	go pki.RotateExpiring(ctx, cfg.Conn)
	return &cfg, nil
}

func (c *Config) appURL() *url.URL {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return &url.URL{}
	}
	return u
}

func (c *Config) FullURL() string {
	u := c.appURL()

	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}

	host := u.Host
	if host == "" {
		host = "localhost"
	}

	// Skip default ports so https://host:443 stays canonical.
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

func (c *Config) WSOrigins() []string {
	origins := make([]string, 0, len(c.AllowedOrigins)+1)
	origins = append(origins, c.FullURL())
	return append(origins, c.AllowedOrigins...)
}

func passkeyOrigins(c *Config) []string {
	origins := []string{c.FullURL()}
	if c.Debug {
		origins = append(origins, "http://localhost:5173")
	}
	return origins
}
