// Package db provides a database connection and querying utilities.
package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mizuchilabs/kagi"
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

	// Pool serves request traffic as AppUser
	// AdminPool serves schema migrations and privileged maintenance as User.
	Pool      *pgxpool.Pool
	AdminPool *pgxpool.Pool
	Q         *Queries
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
	// Create Admin Config (Uses environment PGUSER and PGPASSWORD)
	adminConfig, err := c.poolConfig()
	if err != nil {
		return err
	}
	// Default AppPassword to the environment PGPASSWORD if not provided
	if c.AppPassword == "" {
		c.AppPassword = adminConfig.ConnConfig.Password
	}

	c.AdminPool, err = pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		return fmt.Errorf("creating admin pool: %w", err)
	}

	if c.AutoMigrate {
		if err := c.withSchemaLock(ctx, func() error {
			if err := c.migrate(ctx); err != nil {
				return err
			}
			if err := c.setupAppRole(ctx); err != nil {
				return err
			}
			return c.setupRBACRoles(ctx)
		}); err != nil {
			return err
		}
	}

	// Create App Config
	appConfig, err := c.poolConfig()
	if err != nil {
		return err
	}

	// Override the role and password for runtime traffic
	appConfig.ConnConfig.User = "nokku_app"
	appConfig.ConnConfig.Password = c.AppPassword

	c.Pool, err = pgxpool.NewWithConfig(ctx, appConfig)
	if err != nil {
		return fmt.Errorf("creating app pool: %w", err)
	}
	c.Q = New(c.Pool)

	// Handle shutdown
	go func() {
		<-ctx.Done()
		c.Pool.Close()
		c.AdminPool.Close()
	}()
	return nil
}

// withSchemaLock serializes the full auto-migrate sequence across processes:
// parallel `go test` packages and multiple instances booting at once.
func (c *Connection) withSchemaLock(ctx context.Context, fn func() error) error {
	conn, err := c.AdminPool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring schema lock connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('nokku_schema'))"); err != nil {
		return fmt.Errorf("acquiring schema lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtext('nokku_schema'))")
	}()
	return fn()
}

// setupAppRole grants the runtime role login rights and sets its password.
func (c *Connection) setupAppRole(ctx context.Context) error {
	conn, err := c.AdminPool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('approle'))"); err != nil {
		return fmt.Errorf("acquiring app role lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtext('approle'))")
	}()

	// ALTER ROLE does not accept bind parameters.
	escapedPW := strings.ReplaceAll(c.AppPassword, "'", "''")
	if _, err := conn.Exec(
		ctx,
		"ALTER ROLE nokku_app WITH LOGIN PASSWORD '"+escapedPW+"'",
	); err != nil {
		return fmt.Errorf("granting login to nokku_app: %w", err)
	}
	return nil
}

// WithTx executes a transaction as nokku_system, bypassing rls entirely.
func (c *Connection) WithTx(
	ctx context.Context,
	fn func(*Queries) error,
) error {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE nokku_system"); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	if err := fn(New(tx)); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

// workspaceIDFromContext returns the workspace a request acts in: the tenant
// carried by a machine principal, or the tenant resolved from the request for
// global user principals. It mirrors auth.WorkspaceIDFromContext; db cannot
// import auth, so the small precedence rule lives here too.
func workspaceIDFromContext(ctx context.Context) string {
	if p, ok := kagi.PrincipalFromContext(ctx); ok && p.TenantID != "" {
		return string(p.TenantID)
	}
	t, _ := kagi.TenantFromContext(ctx)
	return string(t)
}

// WithWorkspace executes a transaction scoped to the workspace pinned in the
// request context, as the rls constrained nokku_app role.
func (c *Connection) WithWorkspace(
	ctx context.Context,
	fn func(*Queries) error,
) error {
	actor, ok := kagi.PrincipalFromContext(ctx)
	if !ok || actor.SubjectID == "" {
		return ErrNoActor
	}

	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()

	// Membership and role resolution must see every workspace, so it runs
	// as nokku_system. The transaction switches down to nokku_app before
	// any caller query runs. GUCs are transaction-local and survive the
	// role switch.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE nokku_system"); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	q := New(tx)
	wsIDs, err := q.GetActorWorkspaceIDs(ctx, actor.SubjectID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	workspaceID := ""
	if pinned := workspaceIDFromContext(ctx); pinned != "" {
		if !slices.Contains(wsIDs, pinned) {
			_ = tx.Rollback(ctx)
			return ErrWorkspaceNotAccessible
		}
		workspaceID = pinned
	} else if len(wsIDs) == 1 {
		workspaceID = wsIDs[0]
	}

	if _, err = tx.Exec(
		ctx,
		`SELECT
			set_config('nokku.workspace_id', $1, true),
			set_config('nokku.actor_id', $2, true)
		`,
		workspaceID,
		actor.SubjectID,
	); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE nokku_app"); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	if err := fn(q); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
