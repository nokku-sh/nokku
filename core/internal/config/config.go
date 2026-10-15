package config

import (
	"cmp"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/billing"
	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/email"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/live"
	"github.com/nokku-sh/nokku/core/internal/realip"
	"github.com/nokku-sh/nokku/core/internal/recording"
	"github.com/nokku-sh/nokku/core/internal/ssh"
	"github.com/nokku-sh/nokku/core/internal/storage"
	"github.com/nokku-sh/nokku/core/internal/tenant"
	"github.com/nokku-sh/nokku/core/internal/webpki"
)

// licensePublicKey verifies license keys. Release builds set it with -X, a build without it takes no key.
var licensePublicKey string

// BaseURL is NOKKU_BASE_URL, a host name with an optional port. There is no scheme, see FullURL.
type BaseURL string

// UnmarshalText refuses an IP address too, a browser takes no passkey for it.
func (b *BaseURL) UnmarshalText(text []byte) error {
	raw := strings.ToLower(strings.TrimSpace(string(text)))
	if strings.ContainsAny(raw, "/?#@ ") {
		return errors.New("NOKKU_BASE_URL is a host name with an optional port, like nokku.example.com. " +
			"Leave out the scheme and the path, the server is always reached over https")
	}
	host := raw
	if strings.Contains(raw, ":") {
		h, port, err := net.SplitHostPort(raw)
		if _, perr := strconv.ParseUint(port, 10, 16); err != nil || perr != nil {
			return errors.New("NOKKU_BASE_URL is a host name with an optional port, like nokku.example.com:8443")
		}
		host = h
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return fmt.Errorf("NOKKU_BASE_URL is the IP address %s. Passkeys only work on a host name, "+
			"and the name stays for good. Give the server a name that every machine resolves: a DNS record, "+
			"an entry in the router, or a line in /etc/hosts. localhost is fine for a try on this machine", host)
	}
	*b = BaseURL(raw)
	return nil
}

type EnvConfig struct {
	BaseURL BaseURL `env:"NOKKU_BASE_URL"`
	Port    string  `env:"NOKKU_PORT"     envDefault:"3000"`
	Secret  string  `env:"NOKKU_SECRET"`
	SaaS    bool    `env:"NOKKU_SAAS"`
	Debug   bool
	// TrustedProxies may send plain HTTP and name the client. Unset, that is this machine and the private ranges.
	TrustedProxies []string `env:"NOKKU_TRUSTED_PROXIES" envDefault:"127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"`
}

type Config struct {
	EnvConfig

	Conn         *db.Connection
	IAM          *iam.Service
	Audit        *audit.Service
	Email        *email.Service
	Pool         *daemon.Pool
	Live         *live.Hub
	Storage      *storage.Storage
	Cache        *cache.Memory
	Record       *recording.Service
	Billing      *billing.Stripe
	Entitlements *entitlement.Service
	Tenant       *tenant.Resolver
	WebPKI       *webpki.Identity

	// BootstrapLink signs the self-hosted owner in while they have no passkey. It is logged last.
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
	// Web terminal tickets only. Everything an anonymous caller can write to has a store of its own.
	cfg.Cache = cache.NewMemory(10_000)
	cfg.Live = live.New()
	go cfg.Live.Listen(ctx, cfg.Conn.Pool.Config().ConnConfig)
	cfg.Pool = daemon.New(ctx, cfg.Conn, cfg.Live)
	go cfg.Pool.Listen(ctx, cfg.Conn.Pool.Config().ConnConfig)
	cfg.Email, err = email.New(ctx, cfg.FullURL())
	if err != nil {
		return nil, err
	}

	// Set before anything encrypts. The keyset is wrapped by the KMS key or a key derived from NOKKU_SECRET.
	enc, err := kms.New(ctx, cfg.Conn, cfg.Secret)
	if err != nil {
		return nil, err
	}
	if err := crypto.SetEncryptor(enc); err != nil {
		return nil, err
	}
	enc.Start(ctx)

	cfg.WebPKI, err = webpki.New(ctx, cfg.Conn, cfg.Hostname())
	if err != nil {
		return nil, err
	}

	cfg.Storage, err = storage.New(ctx, cfg.FullURL())
	if err != nil {
		return nil, err
	}
	cfg.Billing, err = billing.New(ctx, cfg.Conn, cfg.SaaS)
	if err != nil {
		return nil, err
	}

	cfg.Entitlements, err = entitlement.New(ctx, cfg.Conn, licensePublicKey, cfg.SaaS)
	if err != nil {
		return nil, err
	}

	// An expired license still starts, refusing here would turn a late renewal into an outage.
	if !cfg.SaaS && enc.UsesKMS() && cfg.Entitlements.License() == nil {
		return nil, fmt.Errorf("external KMS requires an Enterprise license")
	}
	// Self-host makes its one workspace here, the hosted service reads it off the subdomain.
	cfg.Tenant, err = tenant.New(ctx, cfg.Conn, cfg.FullURL(), cfg.SaaS)
	if err != nil {
		return nil, err
	}
	cfg.Audit = audit.New(ctx, cfg.Conn, cfg.Entitlements)
	cfg.Record = recording.New(ctx, cfg.Conn, cfg.Storage, cfg.Entitlements, cfg.Audit)
	go daemon.RetireLoop(ctx, cfg.Conn, cfg.Audit.Record)

	// Its own derived key, so the DPoP nonce HMAC never shares one with the keyset wrap.
	nonceKey, err := hkdf.Key(sha256.New, []byte(cfg.Secret), nil, "nokku dpop nonce v1", 32)
	if err != nil {
		return nil, err
	}
	deps := iam.Deps{
		Conn:         cfg.Conn,
		Audit:        cfg.Audit,
		Secret:       nonceKey,
		Secure:       strings.HasPrefix(cfg.FullURL(), "https://"),
		CanJoin:      cfg.Entitlements.CanInvite,
		StrictEmail:  cfg.SaaS,
		SendNewLogin: cfg.Email.SendNewLoginEmail,
	}
	// Without mail there are no links, the login page then offers passkeys and providers only.
	if cfg.Email.HasSMTP() {
		deps.SendMagicLink = cfg.Email.SendMagicLinkEmail
		deps.SendSignupLink = cfg.Email.SendSignupLinkEmail
	}
	cfg.IAM, err = iam.New(ctx, deps)
	if err != nil {
		return nil, err
	}
	if !cfg.SaaS {
		if cfg.BootstrapLink, err = cfg.IAM.Bootstrap(ctx, cfg.Tenant.Single()); err != nil {
			return nil, err
		}
	}

	go ssh.RotateExpiring(ctx, cfg.Conn)
	return &cfg, nil
}

// Mode is the name the API reports for the mode, the UI switches on it.
func (c *EnvConfig) Mode() string {
	if c.SaaS {
		return "saas"
	}
	return "self_hosted"
}

// FullURL is the public address. The scheme is never configured, plain http only on localhost.
func (c *EnvConfig) FullURL() string {
	if c.Hostname() == "localhost" {
		return "http://" + c.hostPort()
	}
	return "https://" + c.hostPort()
}

func (c *EnvConfig) Hostname() string {
	name, _, _ := strings.Cut(c.hostPort(), ":")
	return name
}

func (c *EnvConfig) hostPort() string {
	return cmp.Or(string(c.BaseURL), "localhost:"+c.Port)
}
