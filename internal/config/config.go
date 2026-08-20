package config

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/caarlos0/env/v11"
	"github.com/mizuchilabs/kagi/cache"
	"github.com/redis/go-redis/v9"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	"github.com/nokku-sh/nokku/internal/geo"
	"github.com/nokku-sh/nokku/internal/storage"
	"github.com/nokku-sh/nokku/internal/util"
)

type EnvConfig struct {
	BaseURL         string `env:"NOKKU_BASE_URL"          envDefault:"http://localhost"`
	Port            string `env:"NOKKU_PORT"              envDefault:"3000"`
	Secret          string `env:"NOKKU_SECRET"`
	DPoPNonceSecret string `env:"NOKKU_DPOP_NONCE_SECRET"`
	Debug           bool
	TrustedProxies  []string `env:"NOKKU_TRUSTED_PROXIES"`
	AllowedOrigins  []string `env:"NOKKU_ALLOWED_ORIGINS"`

	// OAuth configuration
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`
}

type Config struct {
	EnvConfig

	Conn    *db.Connection
	Auth    *auth.Service
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

	cfg.Conn, err = db.NewConnection(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Geo = geo.New()
	cfg.Cache, err = newCache(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Pool = daemon.New(ctx, cfg.Conn)
	nonceSecret := []byte(cfg.DPoPNonceSecret)
	if len(nonceSecret) == 0 {
		nonceSecret = []byte(cfg.Secret)
	}
	cfg.Auth, err = auth.NewService(cfg.Conn, nonceSecret, auth.SSOConfig{
		GoogleClientID:     cfg.GoogleClientID,
		GoogleClientSecret: cfg.GoogleClientSecret,
		GitHubClientID:     cfg.GitHubClientID,
		GitHubClientSecret: cfg.GitHubClientSecret,
		RedirectBase:       cfg.FullURL(),
	})
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

	cfg.Audit, err = audit.New(ctx, cfg.Conn, cfg.Billing)
	if err != nil {
		return nil, err
	}

	if err := crypto.InitDefaultHashers(); err != nil {
		return nil, err
	}

	// NOKKU_SECRET set local secretbox encryption, otherwise KMS-backed.
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

// newCache builds the shared cache. When NOKKU_REDIS_ADDR is set it returns a
// Redis-backed cache, otherwise the single-instance in-memory cache.
func newCache(ctx context.Context) (cache.Cache, error) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		return cache.NewMemory(10_000), nil
	}

	db, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		return nil, fmt.Errorf("cache: invalid REDIS_DB: %w", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       db,
	})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("cache: ping redis: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = client.Close()
	}()

	return cache.NewRedis(client, "nokku:"), nil
}
