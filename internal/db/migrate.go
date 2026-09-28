package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const (
	migrationsVersionTable = "public.schema_migrations"
	baseMigrationVersion   = 1
)

// runMigrations stamps pre-versioned installs as migration 1 instead of
// re-applying, and stamps a database that is ahead after a squash down to the
// newest migration on disk.
func runMigrations(ctx context.Context, conn *pgx.Conn) error {
	// Check before NewMigrator, which creates the table eagerly.
	tableExists, err := versionTableExists(ctx, conn, migrationsVersionTable)
	if err != nil {
		return fmt.Errorf("checking version table: %w", err)
	}
	if !tableExists {
		var hasSchema bool
		if err := conn.QueryRow(ctx,
			"SELECT to_regclass('public.users') IS NOT NULL",
		).Scan(&hasSchema); err != nil {
			return fmt.Errorf("checking existing schema: %w", err)
		}
		if hasSchema {
			// Same shape as tern's own table so later boots migrate normally.
			if _, err := conn.Exec(ctx, fmt.Sprintf(`
				create table if not exists %s(version int4 not null primary key);
				insert into %s(version) select %d where 0=(select count(*) from %s);
			`, migrationsVersionTable, migrationsVersionTable, baseMigrationVersion, migrationsVersionTable)); err != nil {
				return fmt.Errorf("baselining existing schema: %w", err)
			}
			return nil
		}
	}

	m, err := migrate.NewMigrator(ctx, conn, migrationsVersionTable)
	if err != nil {
		return fmt.Errorf("initializing migrator: %w", err)
	}
	migrationFiles, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("opening migrations: %w", err)
	}
	if err := m.LoadMigrations(migrationFiles); err != nil {
		return fmt.Errorf("loading migrations: %w", err)
	}

	// Squashed history, stamp down like `tern override-version`. This cannot
	// tell a squash from an accidentally deleted migration.
	if current, err := m.GetCurrentVersion(ctx); err != nil {
		return fmt.Errorf("reading migration version: %w", err)
	} else if current > int32(len(m.Migrations)) { //#nosec
		slog.Info("migration history squashed, stamping current schema",
			"from", current, "to", len(m.Migrations))
		if err := m.SetVersion(ctx, int32(len(m.Migrations))); err != nil { //#nosec
			return fmt.Errorf("stamping squashed migration history: %w", err)
		}
		return nil
	}

	if err := m.Migrate(ctx); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}

func versionTableExists(ctx context.Context, conn *pgx.Conn, versionTable string) (bool, error) {
	schema, table, _ := strings.Cut(versionTable, ".")
	var count int
	if err := conn.QueryRow(ctx, `
		select count(*) from pg_catalog.pg_tables
		where schemaname = $1 and tablename = $2
	`, schema, table).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
