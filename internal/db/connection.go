// Package db provides a database connection and querying utilities.
package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nokku-sh/nokku/internal/actor"
)

var (
	ErrNoActor                = errors.New("no actor in context")
	ErrWorkspaceNotAccessible = errors.New("workspace is not accessible to actor")
	ErrPermissionDenied       = errors.New("missing required permission")
	ErrWorkspaceNotPinned     = errors.New("operation requires a workspace context")
)

type Connection struct {
	AppPassword string `env:"NOKKU_DB_APP_PASSWORD"`
	AutoMigrate bool   `env:"NOKKU_DB_AUTOMIGRATE"  envDefault:"true"`
	MaxConns    int32  `env:"NOKKU_DB_MAX_CONNS"    envDefault:"10"`
	MinConns    int32  `env:"NOKKU_DB_MIN_CONNS"    envDefault:"0"`

	// Pool serves request traffic as nokku_app, under RLS.
	Pool    *pgxpool.Pool
	sys     *Queries
	sysPool *pgxpool.Pool
}

func NewConnection(ctx context.Context) (*Connection, error) {
	c, err := env.ParseAs[Connection]()
	if err != nil {
		return nil, err
	}

	// Set default environment variables
	defaults := map[string]string{
		"PGHOST":     "localhost",
		"PGPORT":     "5432",
		"PGDATABASE": "nokku",
		"PGUSER":     "postgres",
		"PGPASSWORD": "postgres",
		"PGSSLMODE":  "disable",
	}

	for key, fallback := range defaults {
		// Only set the default if the user hasn't provided the variable
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
	// Runtime traffic never uses the owner role. PGPASSWORD is the fallback
	// so a single-credential dev setup keeps working.
	if c.AppPassword == "" {
		c.AppPassword = appConfig.ConnConfig.Password
	}
	appConfig.ConnConfig.User = "nokku_app"
	appConfig.ConnConfig.Password = c.AppPassword

	c.Pool, err = pgxpool.NewWithConfig(ctx, appConfig)
	if err != nil {
		return fmt.Errorf("creating app pool: %w", err)
	}

	// The system pool logs in as nokku_app too and switches every
	// connection to nokku_system, so no runtime path holds owner rights.
	sysConfig := appConfig.Copy()
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

	go func() {
		<-ctx.Done()
		c.Pool.Close()
		c.sysPool.Close()
	}()
	return nil
}

// setupSchema migrates and seeds roles as the owner (PGUSER), on a short-lived
// pool closed before any request is served.
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

	// Serializes the whole sequence across processes: parallel test packages
	// and multiple instances booting at once.
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

// setupAppRole grants the runtime role login rights and sets its password.
func (c *Connection) setupAppRole(ctx context.Context, conn *pgx.Conn) error {
	// ALTER ROLE does not accept bind parameters, so the statement is built
	// with format() server-side and the password stays a bind parameter.
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

// Sys runs single statements as nokku_system (BYPASSRLS). It is for
// pre-authorization lookups and background jobs, which by definition cannot
// be tenant-scoped. Multi-statement system work uses WithTx.
func (c *Connection) Sys() Querier { return c.sys }

// withTx is the one transaction scaffold: begin, roll back on error or panic,
// otherwise commit. The role and GUC setup that decides whether RLS applies is
// the caller's job, which is what keeps the scope entry points below
// readable as policy instead of plumbing.
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

// Pick the transaction scope by what the query is allowed to see, never by
// convenience:
//
//	Connection.WithWorkspace tenant rows only, pinned to the request's workspace
//	Connection.WithActor     the request's own rows, no tenant pinned
//	Connection.WithTx        every tenant, RLS bypassed
//	Connection.Sys           WithTx for a single statement

// WithTx executes a transaction as nokku_system, bypassing RLS entirely. Only
// cross-tenant work belongs here: the queries see every workspace. Tenant
// scoped work must use WithWorkspace or WithActor.
func (c *Connection) WithTx(
	ctx context.Context,
	fn func(*Queries) error,
) error {
	return withTx(ctx, c.sysPool, func(_ context.Context, _ pgx.Tx, q *Queries) error {
		return fn(q)
	})
}

// WithWorkspace executes a transaction scoped to the workspace pinned in the
// request context, as the RLS constrained nokku_app role. Every query inside
// sees only that workspace's rows.
func (c *Connection) WithWorkspace(
	ctx context.Context,
	fn func(*Queries) error,
) error {
	return withTx(ctx, c.Pool, func(ctx context.Context, tx pgx.Tx, q *Queries) error {
		principal, ok := actor.PrincipalFromContext(ctx)
		if !ok || principal.ID == "" {
			return ErrNoActor
		}

		// The authorization interceptor already resolved the actor's role in
		// this workspace, so membership needs no second lookup.
		if pinned := actor.WorkspaceIDFromContext(ctx); pinned != "" && actor.MemberOf(ctx) == pinned {
			if _, err := tx.Exec(
				ctx,
				`SELECT
					set_config('nokku.actor_id', $1, true),
					set_config('nokku.workspace_id', $2, true)
				`,
				principal.ID,
				pinned,
			); err != nil {
				return err
			}
			return fn(q)
		}

		// Membership and role resolution must see every workspace, so it runs
		// as nokku_system. The transaction switches down to nokku_app before
		// any caller query runs. GUCs are transaction-local and survive the
		// role switch.
		if _, err := tx.Exec(
			ctx,
			`SELECT
				set_config('role', 'nokku_system', true),
				set_config('nokku.actor_id', $1, true)
			`,
			principal.ID,
		); err != nil {
			return err
		}

		wsIDs, err := q.GetActorWorkspaceIDs(ctx, principal.ID)
		if err != nil {
			return err
		}

		workspaceID := ""
		if pinned := actor.WorkspaceIDFromContext(ctx); pinned != "" {
			if !slices.Contains(wsIDs, pinned) {
				return ErrWorkspaceNotAccessible
			}
			workspaceID = pinned
		} else if len(wsIDs) == 1 {
			workspaceID = wsIDs[0]
		}

		if _, err := tx.Exec(
			ctx,
			`SELECT
				set_config('nokku.workspace_id', $1, true),
				set_config('role', 'nokku_app', true)
			`,
			workspaceID,
		); err != nil {
			return err
		}
		return fn(q)
	})
}

// WithActor executes a transaction scoped to a single actor as the RLS
// constrained nokku_app role, without pinning a workspace. It sets only the
// actor GUC so RLS policies governed by current_actor_id() apply (e.g. a
// principal reading its own global audit events). It runs as nokku_app the
// whole time: every query is RLS-filtered, never BYPASSRLS.
func (c *Connection) WithActor(
	ctx context.Context,
	actorID string,
	fn func(*Queries) error,
) error {
	if actorID == "" {
		return ErrNoActor
	}

	return withTx(ctx, c.Pool, func(ctx context.Context, tx pgx.Tx, q *Queries) error {
		// Set the actor GUC transaction-local. Custom GUCs are settable by any
		// role; no role switch is needed.
		if _, err := tx.Exec(
			ctx,
			`SELECT set_config('nokku.actor_id', $1, true)`,
			actorID,
		); err != nil {
			return err
		}
		return fn(q)
	})
}
