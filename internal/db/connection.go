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

	if err := c.createPools(ctx); err != nil {
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

func (c *Connection) createPools(ctx context.Context) error {
	if c.AutoMigrate {
		if err := c.setupSchema(ctx); err != nil {
			return err
		}
	}

	appConfig, err := c.poolConfig()
	if err != nil {
		return err
	}
	// Falling back to PGPASSWORD keeps single-credential dev setups working.
	if c.AppPassword == "" {
		c.AppPassword = appConfig.ConnConfig.Password
	}
	appConfig.ConnConfig.User = "nokku_app"
	appConfig.ConnConfig.Password = c.AppPassword
	appConfig.PrepareConn = pinWorkspace

	c.Pool, err = pgxpool.NewWithConfig(ctx, appConfig)
	if err != nil {
		return fmt.Errorf("creating app pool: %w", err)
	}
	c.tenant = New(c.Pool)

	// The system pool logs in as nokku_app too and switches every
	// connection to nokku_system, so no runtime path holds owner rights.
	sysConfig := appConfig.Copy()
	// Never pinned. A pin left on a system connection would send an insert
	// that names no workspace into whatever workspace was pinned last.
	sysConfig.PrepareConn = nil
	sysConfig.MaxConns = min(c.MaxConns, 4)
	sysConfig.MinConns = min(c.MinConns, sysConfig.MaxConns)
	sysConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE nokku_system")
		return err
	}
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
func (c *Connection) setupSchema(ctx context.Context) error {
	adminConfig, err := c.poolConfig()
	if err != nil {
		return err
	}
	adminConfig.MaxConns = 1
	adminConfig.MinConns = 0
	if c.AppPassword == "" {
		c.AppPassword = adminConfig.ConnConfig.Password
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		return fmt.Errorf("creating admin pool: %w", err)
	}
	defer admin.Close()

	conn, err := admin.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring admin connection: %w", err)
	}
	defer conn.Release()

	// Serializes instances booting at once. The lock is per database, so test
	// packages on their own databases still race on the cluster-wide role.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('nokku_schema'))"); err != nil {
		return fmt.Errorf("acquiring schema lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock(hashtext('nokku_schema'))")
	}()

	if err := runMigrations(ctx, conn.Conn()); err != nil {
		return err
	}
	return c.setupAppRole(ctx, conn.Conn())
}

func (c *Connection) setupAppRole(ctx context.Context, conn *pgx.Conn) error {
	// ALTER ROLE takes no bind parameters, so format() quotes it server-side.
	var stmt string
	if err := conn.QueryRow(
		ctx,
		"SELECT format('ALTER ROLE nokku_app WITH LOGIN PASSWORD %L', $1::text)",
		c.AppPassword,
	).Scan(&stmt); err != nil {
		return fmt.Errorf("building role statement: %w", err)
	}
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("granting login to nokku_app: %w", err)
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

// Tenant runs single statements as nokku_app, each pinned to the workspace
// on its context. Statements that belong together go through WithWorkspace.
func (c *Connection) Tenant() *Queries { return c.tenant }

// Sys runs single statements as nokku_system (BYPASSRLS), for pre-auth
// lookups and jobs.
func (c *Connection) Sys() *Queries { return c.sys }

func withTx(
	ctx context.Context,
	pool *pgxpool.Pool,
	fn func(context.Context, pgx.Tx, *Queries) error,
) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err := fn(ctx, tx, New(tx)); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// Pick the scope by what the query may see, never by convenience:
//
//	Tenant         tenant rows of the pinned workspace, RLS enforced
//	WithWorkspace  Tenant for statements that belong in one transaction
//	Sys            every tenant, RLS bypassed, only boot, webhooks and jobs
//	WithTx         Sys for statements that belong in one transaction
//
// Tenant queries carry no workspace filter and tenant inserts no workspace
// id, the pin is the only scope they have. Run as system they would reach
// every workspace, so system code only calls queries that name the workspace
// or are cross-tenant on purpose.

// WithTx bypasses RLS, only cross-tenant work belongs here.
func (c *Connection) WithTx(
	ctx context.Context,
	fn func(*Queries) error,
) error {
	return withTx(ctx, c.sysPool, func(_ context.Context, _ pgx.Tx, q *Queries) error {
		return fn(q)
	})
}

// WithWorkspace runs fn in a transaction of the workspace on the context. The
// tenant middleware put it there, so a request without one fails closed.
// Work outside a request pins one with actor.WithWorkspace. The pin itself
// happens when the connection leaves the pool, see pinWorkspace.
func (c *Connection) WithWorkspace(
	ctx context.Context,
	fn func(*Queries) error,
) error {
	return withTx(ctx, c.Pool, func(_ context.Context, _ pgx.Tx, q *Queries) error {
		return fn(q)
	})
}
