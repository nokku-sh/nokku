// Package db provides a database connection and querying utilities.
package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nokku-sh/nokku/internal/meta"
)

var ErrNoWorkspaces = errors.New("actor has no assigned workspaces")

type Connection struct {
	Host        string `env:"NOKKU_DB_HOST"        envDefault:"localhost"`
	Port        string `env:"NOKKU_DB_PORT"        envDefault:"5432"`
	Database    string `env:"NOKKU_DB_NAME"        envDefault:"nokku"`
	User        string `env:"NOKKU_DB_USER"        envDefault:"postgres"`
	Password    string `env:"NOKKU_DB_PASSWORD"    envDefault:"postgres"`
	SSLMode     string `env:"NOKKU_DB_SSL_MODE"    envDefault:"disable"`
	AutoMigrate bool   `env:"NOKKU_DB_AUTOMIGRATE" envDefault:"true"`

	Pool *pgxpool.Pool
	Q    *Queries
}

func NewConnection(ctx context.Context) (*Connection, error) {
	c, err := env.ParseAs[Connection]()
	if err != nil {
		return nil, err
	}

	if err := c.createPool(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Connection) createPool(ctx context.Context) error {
	url := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)

	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return fmt.Errorf("parsing pool config: %w", err)
	}
	config.MaxConns = 10
	config.MinConns = 0
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = time.Minute
	config.ConnConfig.ConnectTimeout = 5 * time.Second

	c.Pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("creating pool: %w", err)
	}
	c.Q = New(c.Pool)

	if c.AutoMigrate {
		if err := c.Migrate(ctx); err != nil {
			return err
		}
		if err := c.EnsureRoles(ctx); err != nil {
			return err
		}
	}

	// Handle shutdown
	go func() {
		<-ctx.Done()
		c.Pool.Close()
	}()
	return nil
}

// WithTx executes a transaction.
func (c *Connection) WithTx(ctx context.Context, fn func(q *Queries) error) error {
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

	q := New(tx)
	if err := fn(q); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

// WithWorkspace executes a transaction scoped to the correct workspace.
func (c *Connection) WithWorkspace(ctx context.Context, fn func(*Queries) error) error {
	actor := meta.ActorFromContext(ctx)
	if actor.ID == "" {
		return errors.New("no actor in context")
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

	// Fetch workspace IDs fresh from the database.
	// Covers users (workspace_members), agents, and service accounts.
	wsIDs, err := New(tx).GetActorWorkspaceIDs(ctx, actor.ID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if len(wsIDs) == 0 {
		_ = tx.Rollback(ctx)
		return ErrNoWorkspaces
	}

	if _, err = tx.Exec(
		ctx, `
		SELECT 
			set_config('nokku.workspace_ids', $1, true),
			set_config('nokku.actor_type', $2, true),
			set_config('nokku.user_id', $3, true)
	`,
		strings.Join(wsIDs, ","),
		string(actor.Type),
		actor.ID,
	); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE nokku_app"); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	if err := fn(New(tx)); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
