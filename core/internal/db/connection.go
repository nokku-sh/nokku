package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nokku-sh/nokku/core/internal/actor"
)

// ServerLock is held shared by a running core. TryAdvisoryXactLock on it fails
// while one runs, with the same key space as pg_advisory_lock_shared.
const ServerLock = "nokku_server"

var (
	ErrPermissionDenied   = errors.New("missing required permission")
	ErrWorkspaceNotPinned = errors.New("no workspace on the request")
)

type Connection struct {
	AppPassword string `env:"NOKKU_DB_APP_PASSWORD"`
	MaxConns    int32  `env:"NOKKU_DB_MAX_CONNS"    envDefault:"20"`

	// Pool serves request traffic as nokku_app, under RLS.
	Pool    *pgxpool.Pool
	tenant  *Queries
	sys     *Queries
	sysPool *pgxpool.Pool
}

// Migrate alone logs in as the owner role (PGUSER), only the server runs it.
func Migrate(ctx context.Context) error {
	c, config, err := settings()
	if err != nil {
		return err
	}
	return c.setupSchema(ctx, config.ConnConfig)
}

// NewConnection changes nothing in the database, the server may be running.
func NewConnection(ctx context.Context) (*Connection, error) {
	c, config, err := settings()
	if err != nil {
		return nil, err
	}
	if err := c.createPools(ctx, config); err != nil {
		return nil, err
	}
	return c, nil
}

func settings() (*Connection, *pgxpool.Config, error) {
	c, err := env.ParseAs[Connection]()
	if err != nil {
		return nil, nil, err
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
		if os.Getenv(key) != "" {
			continue
		}
		_ = os.Setenv(key, fallback)
		if key == "PGPASSWORD" || key == "PGSSLMODE" {
			slog.Warn(key + " is not set, the default is only fit for a local try")
		}
	}

	config, err := c.poolConfig()
	if err != nil {
		return nil, nil, err
	}
	// Falling back to PGPASSWORD keeps single-credential dev setups working.
	if c.AppPassword == "" {
		c.AppPassword = config.ConnConfig.Password
	}
	return &c, config, nil
}

func (c *Connection) poolConfig() (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("parsing pool config: %w", err)
	}
	if c.MaxConns < 1 {
		return nil, fmt.Errorf("NOKKU_DB_MAX_CONNS must be greater than zero")
	}
	config.MaxConns = c.MaxConns
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = time.Minute
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	// A cached plan is costed for one workspace, then reused for all others.
	config.ConnConfig.RuntimeParams["plan_cache_mode"] = "force_custom_plan"
	// Compiling a query costs more than it saves on requests this short.
	config.ConnConfig.RuntimeParams["jit"] = "off"
	return config, nil
}

// Two runtime roles, so no runtime path holds owner rights.
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
	// Never pinned, a leftover pin would send an insert to the wrong workspace.
	sysConfig.PrepareConn = nil
	sysConfig.MaxConns = min(c.MaxConns, 4)
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

func (c *Connection) setupSchema(ctx context.Context, owner *pgx.ConnConfig) error {
	conn, err := pgx.ConnectConfig(ctx, owner)
	if err != nil {
		return fmt.Errorf("connecting as owner: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))

	// Serializes boots. Per database, so test packages still race on the roles.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('nokku_schema'))"); err != nil {
		return fmt.Errorf("acquiring schema lock: %w", err)
	}
	if err := runMigrations(ctx, conn); err != nil {
		return err
	}
	return c.setupRoles(ctx, conn)
}

// The migration creates the runtime roles without a password.
func (c *Connection) setupRoles(ctx context.Context, conn *pgx.Conn) error {
	for _, role := range []string{"nokku_app", "nokku_system"} {
		// ALTER ROLE takes no bind parameters, format() quotes it server-side.
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

// pinWorkspace runs on every acquire and refuses a ctx without a workspace.
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

// System code only calls queries that name the workspace.

// Tenant runs as nokku_app, each statement pinned to the ctx's workspace.
func (c *Connection) Tenant() *Queries { return c.tenant }

// TenantTx fails closed without a workspace, actor.WithWorkspace pins one.
func (c *Connection) TenantTx(ctx context.Context, fn func(*Queries) error) error {
	return pgx.BeginFunc(ctx, c.Pool, func(tx pgx.Tx) error { return fn(New(tx)) })
}

// HoldServerLock marks this process as a running core until ctx ends. A lost
// connection drops the mark too, it only catches a mistake.
func (c *Connection) HoldServerLock(ctx context.Context) error {
	conn, err := pgx.ConnectConfig(ctx, c.sysPool.Config().ConnConfig)
	if err != nil {
		return fmt.Errorf("connecting for the server lock: %w", err)
	}
	context.AfterFunc(ctx, func() { _ = conn.Close(context.WithoutCancel(ctx)) })
	_, err = conn.Exec(ctx, "SELECT pg_advisory_lock_shared(hashtext($1))", ServerLock)
	return err
}

// Sys runs as nokku_system (BYPASSRLS), for pre-auth lookups and jobs.
func (c *Connection) Sys() *Queries { return c.sys }

// SysTx bypasses RLS, only cross-tenant work belongs here.
func (c *Connection) SysTx(ctx context.Context, fn func(*Queries) error) error {
	return pgx.BeginFunc(ctx, c.sysPool, func(tx pgx.Tx) error { return fn(New(tx)) })
}
