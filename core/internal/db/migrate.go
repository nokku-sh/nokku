package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func runMigrations(ctx context.Context, conn *pgx.Conn) error {
	m, err := migrate.NewMigrator(ctx, conn, "public.schema_version")
	if err != nil {
		return fmt.Errorf("initializing migrator: %w", err)
	}
	files, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("opening migrations: %w", err)
	}
	if err := m.LoadMigrations(files); err != nil {
		return fmt.Errorf("loading migrations: %w", err)
	}
	if err := m.Migrate(ctx); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}
