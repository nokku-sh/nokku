package config

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/caarlos0/env/v11"
	"github.com/mizuchilabs/kagi"
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
	BaseURL        string `env:"NOKKU_BASE_URL"          envDefault:"http://localhost"`
	Port           string `env:"NOKKU_PORT"              envDefault:"3000"`
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
	Auth    *auth.Runtime
	Audit   *audit.Service
	Email   *email.Service
	Pool    *daemon.Pool
	Storage storage.Store
	Cache   kagi.Cache
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

	// kagi owns identity and its store migrates its own schema on Open, so
	// it must come up before the nokku schema migration, which references
	// kagi.users cross-schema.
	kagiStore, err := auth.OpenStore(ctx)
	if err != nil {
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
	cfg.Email, err = email.New(cfg.FullURL(), cfg.Cache)
	if err != nil {
		return nil, err
	}
	// NOKKU_SECRET keys the default at-rest encryption: nokku's secretbox
	// for CA private keys and recordings, and kagi derives its cipher and
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

	// KMS mode replaces the encryptor before anything can encrypt. The
	// TinkEncryptor satisfies kagi.Cipher, so kagi's SSO client secrets
	// and SAML SP key follow the same path; only the DPoP nonce key keeps
	// deriving from NOKKU_SECRET, which is stateless and needs no KMS.
	var kmsCipher kagi.Cipher
	if os.Getenv("KMS_URI") != "" {
		enc, err := kms.New(ctx, cfg.Conn)
		if err != nil {
			return nil, err
		}
		if err := crypto.SetEncryptor(enc); err != nil {
			return nil, err
		}
		enc.Start(ctx)
		kmsCipher = enc
	}

	cfg.Auth, err = auth.New(ctx, auth.Deps{
		Store:              kagiStore,
		Conn:               cfg.Conn,
		Cache:              cfg.Cache,
		Email:              cfg.Email,
		BaseURL:            cfg.FullURL(),
		Secret:             []byte(cfg.Secret),
		Cipher:             kmsCipher,
		GoogleClientID:     cfg.GoogleClientID,
		GoogleClientSecret: cfg.GoogleClientSecret,
		GitHubClientID:     cfg.GitHubClientID,
		GitHubClientSecret: cfg.GitHubClientSecret,
		Debug:              cfg.Debug,
	})
	if err != nil {
		return nil, err
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

	cfg.Audit, err = audit.New(ctx, cfg.Conn, cfg.Billing, kagiUserDirectory{svc: cfg.Auth.Service()})
	if err != nil {
		return nil, err
	}
	// Auth events (login, register, SSO denial, ...) flow into the audit log
	// via the kagi sink. The audit service needs the DB and billing so it is
	// built after auth and attached here, before the server serves traffic.
	cfg.Auth.Service().Events = cfg.Audit
	// Account deletion cascades nokku's account-scoped data (avatar storage,
	// subscriptions, owned workspaces) before kagi deletes the identity. The
	// hook is attached here because it needs billing, which is built last.
	cfg.Auth.Account.OnDelete = func(ctx context.Context, u kagi.User) error {
		return deleteAccountData(ctx, &cfg, u)
	}
	if err := crypto.InitDefaultHashers(); err != nil {
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

// newCache builds the shared cache. When REDIS_ADDR is set it returns a
// Redis-backed cache, otherwise the single-instance in-memory cache.
func newCache(ctx context.Context) (kagi.Cache, error) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		return kagi.NewMemoryCache(10_000), nil
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

	return kagi.NewRedisCache(client, "nokku:"), nil
}

// kagiUserDirectory adapts kagi's store to audit's UserDirectory: it resolves
// an actor id to its kagi user. nokku's users are global, so the tenant is
// the empty value.
type kagiUserDirectory struct {
	svc *kagi.Service
}

func (d kagiUserDirectory) GetUser(ctx context.Context, userID string) (kagi.User, error) {
	return d.svc.Users.Get(ctx, "", userID)
}

// deleteAccountData cascades the nokku-owned half of an account before kagi
// deletes the identity: the stored avatar, the owned workspaces' billing, and
// the workspaces themselves. Membership rows cascade through the kagi.users
// foreign keys.
func deleteAccountData(ctx context.Context, cfg *Config, u kagi.User) error {
	if err := cfg.Storage.Delete(ctx, storage.AvatarPath(u.ID)); err != nil {
		slog.Warn("failed to delete avatar", "error", err)
	}
	return cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		workspaceIDs, err := q.GetWorkspacesByOwner(ctx, u.ID)
		if err != nil {
			return err
		}
		for _, workspaceID := range workspaceIDs {
			if !cfg.Billing.Enabled() {
				break
			}
			if err := cfg.Billing.Cancel(ctx, workspaceID, true, ""); err != nil {
				slog.Warn("failed to cancel subscription", "error", err)
			}
		}
		return q.DeleteWorkspacesByOwner(ctx, u.ID)
	})
}
