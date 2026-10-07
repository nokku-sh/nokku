package config

import (
	"cmp"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"

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
	"github.com/nokku-sh/nokku/internal/realip"
	"github.com/nokku-sh/nokku/internal/recording"
	"github.com/nokku-sh/nokku/internal/storage"
	"github.com/nokku-sh/nokku/internal/tenant"
)

type EnvConfig struct {
	BaseURL        string `env:"NOKKU_BASE_URL"`
	Port           string `env:"NOKKU_PORT"            envDefault:"3000"`
	Secret         string `env:"NOKKU_SECRET"`
	Debug          bool
	TrustedProxies []string `env:"NOKKU_TRUSTED_PROXIES"`
}

type Config struct {
	EnvConfig

	Conn         *db.Connection
	IAM          *iam.Service
	Audit        *audit.Service
	Email        *email.Service
	Pool         *daemon.Pool
	Storage      *storage.Storage
	Cache        *cache.Memory
	Record       *recording.Service
	Billing      *billing.Service
	Entitlements *entitlement.Service
	Tenant       *tenant.Resolver

	// BootstrapLink signs the self-hosted owner in while they have no passkey.
	// The server shows it once it listens, so it is the last thing in the log.
	BootstrapLink string
}

func New(ctx context.Context, cmd *cli.Command) (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, err
	}
	if err := kms.ValidSecret(cfg.Secret); err != nil {
		return nil, err
	}

	if cmd != nil {
		cfg.Debug = cmd.Bool("debug")
	}

	if err := realip.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, err
	}

	cfg.Conn, err = db.NewConnection(ctx)
	if err != nil {
		return nil, err
	}
	// Web terminal tickets only, written by signed-in members. Everything an
	// anonymous caller can write to has a store of its own.
	cfg.Cache = cache.NewMemory(10_000)
	cfg.Pool = daemon.New(ctx, cfg.Conn)
	go cfg.Pool.Listen(ctx, cfg.Conn.Pool.Config().ConnConfig)
	cfg.Email, err = email.New(cfg.FullURL())
	if err != nil {
		return nil, err
	}

	// Set before anything encrypts. The keyset is wrapped by the KMS key, or
	// by a key derived from NOKKU_SECRET.
	enc, err := kms.New(ctx, cfg.Conn, cfg.Secret)
	if err != nil {
		return nil, err
	}
	if err := crypto.SetEncryptor(enc); err != nil {
		return nil, err
	}
	enc.Start(ctx)

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
	if mode == entitlement.ModeSelfHosted && enc.UsesKMS() && cfg.Entitlements.License() == nil {
		return nil, fmt.Errorf("external KMS requires an Enterprise license")
	}
	// The resolver runs before every request. Self-host makes its one
	// workspace here, the hosted service reads it off the subdomain.
	cfg.Tenant, err = tenant.New(ctx, cfg.Conn, cfg.FullURL(), mode == entitlement.ModeSaaS)
	if err != nil {
		return nil, err
	}
	cfg.Audit, err = audit.New(ctx, cfg.Conn, cfg.Entitlements)
	if err != nil {
		return nil, err
	}
	cfg.Record = recording.New(ctx, cfg.Conn, cfg.Storage, cfg.Entitlements, cfg.Audit)

	// Its own derived key, so the DPoP nonce HMAC never shares one with the
	// keyset wrap.
	nonceKey, err := hkdf.Key(sha256.New, []byte(cfg.Secret), nil, "nokku dpop nonce v1", 32)
	if err != nil {
		return nil, err
	}
	cfg.IAM, err = iam.New(ctx, iam.Deps{
		Conn:        cfg.Conn,
		Events:      cfg.Audit,
		Secret:      nonceKey,
		Secure:      strings.HasPrefix(cfg.FullURL(), "https://"),
		Debug:       cfg.Debug,
		CanJoin:     cfg.Entitlements.CanInvite,
		StrictEmail: mode == entitlement.ModeSaaS,
	})
	if err != nil {
		return nil, err
	}
	if mode == entitlement.ModeSelfHosted {
		if cfg.BootstrapLink, err = cfg.IAM.Bootstrap(ctx, cfg.Tenant.Single()); err != nil {
			return nil, err
		}
	}

	go pki.RotateExpiring(ctx, cfg.Conn)
	return &cfg, nil
}

// FullURL is NOKKU_BASE_URL as given, the public address. The listen port is
// not part of it, a reverse proxy usually sits in between. Unset, it is the
// local listener.
func (c *Config) FullURL() string {
	if c.BaseURL == "" {
		return "http://localhost:" + c.Port
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return "http://localhost:" + c.Port
	}
	return cmp.Or(u.Scheme, "http") + "://" + cmp.Or(u.Host, "localhost")
}
