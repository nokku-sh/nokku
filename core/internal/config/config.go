package config

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/core/internal/access"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/billing"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/email"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/realip"
	"github.com/nokku-sh/nokku/core/internal/recording"
	"github.com/nokku-sh/nokku/core/internal/storage"
	"github.com/nokku-sh/nokku/core/internal/tenant"
)

// Set with -X in release builds, a build without it takes no license key.
var licensePublicKey string

// BaseURL is a host name with an optional port and no scheme, see FullURL.
type BaseURL string

type EnvConfig struct {
	BaseURL BaseURL `env:"NOKKU_BASE_URL"`
	Port    string  `env:"NOKKU_PORT"     envDefault:"3000"`
	SaaS    bool    `env:"NOKKU_SAAS"`
	Debug   bool
	// TrustedProxies may name the client, which source-address options match
	// against. Unset, that is any peer on loopback or a private network.
	TrustedProxies []string `env:"NOKKU_TRUSTED_PROXIES"`
}

type Config struct {
	EnvConfig

	Conn         *db.Connection
	Keyset       *kms.Keyset
	IAM          *iam.Service
	Audit        *audit.Service
	Email        *email.Service
	Pool         *daemon.Pool
	Record       *recording.Service
	Billing      *billing.Stripe
	Entitlements *entitlement.Service
	Tenant       *tenant.Resolver

	// OwnerNeedsLink is set while the owner has no passkey or provider yet.
	OwnerNeedsLink bool
}

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

func New(ctx context.Context, cmd *cli.Command) (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, err
	}
	if cmd != nil {
		cfg.Debug = cmd.Bool("debug")
	}

	if err := realip.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, err
	}
	if err = db.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrating the database: %w", err)
	}
	cfg.Conn, err = db.NewConnection(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Pool = daemon.New(cfg.Conn)
	go cfg.Pool.Listen(ctx, cfg.Conn.Pool.Config().ConnConfig)
	cfg.Email, err = email.New(ctx, cfg.FullURL())
	if err != nil {
		return nil, err
	}

	cfg.Keyset, err = kms.New(ctx, cfg.Conn, cfg.SaaS)
	if err != nil {
		return nil, err
	}

	store, err := storage.New(ctx)
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

	// Self-host makes its one workspace here, hosted reads the subdomain.
	cfg.Tenant, err = tenant.New(ctx, cfg.Conn, cfg.Keyset, cfg.FullURL(), cfg.SaaS)
	if err != nil {
		return nil, err
	}
	cfg.Audit, err = audit.New(ctx, cfg.Conn, cfg.Keyset, cfg.Entitlements)
	if err != nil {
		return nil, err
	}
	cfg.Record = recording.New(ctx, cfg.Conn, cfg.Keyset, store, cfg.Entitlements, cfg.Audit)
	cfg.Pool.Record = cfg.Audit.Record
	go daemon.RetireLoop(ctx, cfg.Conn, cfg.Pool.Connected, cfg.Audit.Record)
	go access.ExpireLoop(ctx, cfg.Conn, cfg.Audit.Append)
	go cfg.Keyset.VaultTokenLoop(ctx)

	deps := iam.Deps{
		Conn:         cfg.Conn,
		Keyset:       cfg.Keyset,
		Audit:        cfg.Audit,
		Secure:       strings.HasPrefix(cfg.FullURL(), "https://"),
		CanJoin:      cfg.Entitlements.CanInvite,
		StrictEmail:  cfg.SaaS,
		SendNewLogin: cfg.Email.SendNewLoginEmail,
		SendNewWayIn: cfg.Email.SendNewWayInEmail,
	}
	// No mail, no links. The login page then offers passkeys and providers.
	if cfg.Email.HasSMTP() {
		deps.SendMagicLink = cfg.Email.SendMagicLinkEmail
		deps.SendInvite = cfg.Email.SendInviteEmail
	}
	cfg.IAM, err = iam.New(ctx, deps)
	if err != nil {
		return nil, err
	}
	if !cfg.SaaS {
		if cfg.OwnerNeedsLink, err = cfg.IAM.Bootstrap(ctx, cfg.Tenant.Single()); err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

// Mode is what the API reports, the UI switches on it.
func (c *EnvConfig) Mode() string {
	if c.SaaS {
		return "saas"
	}
	return "self_hosted"
}

// FullURL is the public address, plain http only on localhost.
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
