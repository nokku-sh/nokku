// Package db provides a database connection and querying utilities.
package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nokku-sh/nokku/internal/actor"
)

var (
	ErrPermissionDenied   = errors.New("missing required permission")
	ErrWorkspaceNotPinned = errors.New("no workspace on the request")
)

type Connection struct {
	AppPassword string `env:"NOKKU_DB_APP_PASSWORD"`
	AutoMigrate bool   `env:"NOKKU_DB_AUTOMIGRATE"  envDefault:"true"`
	MaxConns    int32  `env:"NOKKU_DB_MAX_CONNS"    envDefault:"10"`
	MinConns    int32  `env:"NOKKU_DB_MIN_CONNS"    envDefault:"0"`

	// Pool serves request traffic as nokku_app, under RLS.
	Pool    *pgxpool.Pool
	tenant  *Queries
	sys     *Queries
	sysPool *pgxpool.Pool
}

func NewConnection(ctx context.Context) (*Connection, error) {
	c, err := env.ParseAs[Connection]()
	if err != nil {
		return nil, err
	}

	defaults := map[string]string{
		"PGHOST":     "localhost",
		"PGPORT":     "5432",
		"PGDATABASE": "nokku",
		"PGUSER":     "postgres",
		"PGPASSWORD": "postgres",
		"PGSSLMODE":  "disable",
	}

	for key, fallback := range defaults {
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, fallback)
		}
	}

	config, err := c.poolConfig()
	if err != nil {
		return nil, err
	}
	// Falling back to PGPASSWORD keeps single-credential dev setups working.
	if c.AppPassword == "" {
		c.AppPassword = config.ConnConfig.Password
	}
	if c.AutoMigrate {
		if err := c.setupSchema(ctx, config.ConnConfig); err != nil {
			return nil, err
		}
	}
	if err := c.createPools(ctx, config); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Connection) poolConfig() (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("parsing pool config: %w", err)
	}
	if c.MaxConns < 1 {
		return nil, fmt.Errorf("NOKKU_DB_MAX_CONNS must be greater than zero")
	}
	if c.MinConns < 0 || c.MinConns > c.MaxConns {
		return nil, fmt.Errorf("NOKKU_DB_MIN_CONNS must be between zero and NOKKU_DB_MAX_CONNS")
	}
	config.MaxConns = c.MaxConns
	config.MinConns = c.MinConns
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = time.Minute
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	return config, nil
}

// createPools logs in as the two runtime roles, so no runtime path holds
// owner rights.
func (c *Connection) createPools(ctx context.Context, appConfig *pgxpool.Config) error {
	appConfig.ConnConfig.User = "nokku_app"
	appConfig.ConnConfig.Password = c.AppPassword
	appConfig.PrepareConn = pinWorkspace

	var err error
	c.Pool, err = pgxpool.NewWithConfig(ctx, appConfig)
	if err != nil {
		return fmt.Errorf("creating app pool: %w", err)
	}
	c.tenant = New(c.Pool)

	sysConfig := appConfig.Copy()
	sysConfig.ConnConfig.User = "nokku_system"
	// Never pinned. A pin left on a system connection would send an insert
	// that names no workspace into whatever workspace was pinned last.
	sysConfig.PrepareConn = nil
	sysConfig.MaxConns = min(c.MaxConns, 4)
	sysConfig.MinConns = min(c.MinConns, sysConfig.MaxConns)
	c.sysPool, err = pgxpool.NewWithConfig(ctx, sysConfig)
	if err != nil {
		c.Pool.Close()
		return fmt.Errorf("creating system pool: %w", err)
	}
	c.sys = New(c.sysPool)

	context.AfterFunc(ctx, func() {
		c.Pool.Close()
		c.sysPool.Close()
	})
	return nil
}

// setupSchema is the only place the owner role (PGUSER) is used.
func (c *Connection) setupSchema(ctx context.Context, owner *pgx.ConnConfig) error {
	conn, err := pgx.ConnectConfig(ctx, owner)
	if err != nil {
		return fmt.Errorf("connecting as owner: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))

	// Serializes instances booting at once, the session holds it until it
	// closes. The lock is per database, so test packages on their own
	// databases still race on the cluster-wide roles.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('nokku_schema'))"); err != nil {
		return fmt.Errorf("acquiring schema lock: %w", err)
	}
	if err := runMigrations(ctx, conn); err != nil {
		return err
	}
	return c.setupRoles(ctx, conn)
}

// setupRoles lets the two runtime roles log in, the migration creates them
// without a password.
func (c *Connection) setupRoles(ctx context.Context, conn *pgx.Conn) error {
	for _, role := range []string{"nokku_app", "nokku_system"} {
		// ALTER ROLE takes no bind parameters, so format() quotes it server-side.
		var stmt string
		if err := conn.QueryRow(
			ctx,
			"SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L', $1::text, $2::text)",
			role, c.AppPassword,
		).Scan(&stmt); err != nil {
			return fmt.Errorf("building role statement: %w", err)
		}
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("granting login to %s: %w", role, err)
		}
	}
	return nil
}

// pinWorkspace runs every time a connection leaves the request pool. It pins
// the workspace of the caller's context for as long as the caller holds the
// connection. Without a workspace the caller gets an error, so a connection
// is never used under the pin its last user left behind.
func pinWorkspace(ctx context.Context, conn *pgx.Conn) (bool, error) {
	ws := actor.WorkspaceIDFromContext(ctx)
	if ws == "" {
		return true, ErrWorkspaceNotPinned
	}
	if _, err := conn.Exec(ctx, `SELECT set_config('nokku.workspace_id', $1, false)`, ws); err != nil {
		return false, err
	}
	return true, nil
}

// Pick the scope by what the query may see, never by convenience:
//
//	Tenant    tenant rows of the pinned workspace, RLS enforced
//	TenantTx  Tenant for statements that belong in one transaction
//	Sys       every tenant, RLS bypassed, only boot, webhooks and jobs
//	SysTx     Sys for statements that belong in one transaction
//
// Tenant queries carry no workspace filter and tenant inserts no workspace
// id, the pin is the only scope they have. Run as system they would reach
// every workspace, so system code only calls queries that name the workspace
// or are cross-tenant on purpose.

// Tenant runs single statements as nokku_app, each pinned to the workspace
// on its context. Statements that belong together go through TenantTx.
func (c *Connection) Tenant() *Queries { return c.tenant }

// TenantTx runs fn in a transaction of the workspace on the context. The
// tenant middleware put it there, so a request without one fails closed.
// Work outside a request pins one with actor.WithWorkspace. The pin itself
// happens when the connection leaves the pool, see pinWorkspace.
func (c *Connection) TenantTx(ctx context.Context, fn func(*Queries) error) error {
	return pgx.BeginFunc(ctx, c.Pool, func(tx pgx.Tx) error { return fn(New(tx)) })
}

// Sys runs single statements as nokku_system (BYPASSRLS), for pre-auth
// lookups and jobs.
func (c *Connection) Sys() *Queries { return c.sys }

// SysTx bypasses RLS, only cross-tenant work belongs here.
func (c *Connection) SysTx(ctx context.Context, fn func(*Queries) error) error {
	return pgx.BeginFunc(ctx, c.sysPool, func(tx pgx.Tx) error { return fn(New(tx)) })
}
