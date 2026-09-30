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

// Sys runs single statements as nokku_system (BYPASSRLS), for pre-auth
// lookups and jobs.
func (c *Connection) Sys() Querier { return c.sys }

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
//	WithWorkspace  tenant rows, pinned to the request's workspace
//	WithActor      the request's own rows, no tenant pinned
//	WithTx         every tenant, RLS bypassed
//	Sys            WithTx for a single statement

// WithTx bypasses RLS, only cross-tenant work belongs here.
func (c *Connection) WithTx(
	ctx context.Context,
	fn func(*Queries) error,
) error {
	return withTx(ctx, c.sysPool, func(_ context.Context, _ pgx.Tx, q *Queries) error {
		return fn(q)
	})
}

func (c *Connection) WithWorkspace(
	ctx context.Context,
	fn func(*Queries) error,
) error {
	return withTx(ctx, c.Pool, func(ctx context.Context, tx pgx.Tx, q *Queries) error {
		principal, ok := actor.PrincipalFromContext(ctx)
		if !ok || principal.ID == "" {
			return ErrNoActor
		}

		// Authorization already verified the membership.
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

		// Membership lookup must see every workspace, so it runs as
		// nokku_system and drops to nokku_app before any caller query.
		// Transaction-local GUCs survive the role switch.
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

// WithActor stays nokku_app the whole time, so every query is RLS-filtered.
func (c *Connection) WithActor(
	ctx context.Context,
	actorID string,
	fn func(*Queries) error,
) error {
	if actorID == "" {
		return ErrNoActor
	}

	return withTx(ctx, c.Pool, func(ctx context.Context, tx pgx.Tx, q *Queries) error {
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
