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

// migrate brings the database schema up to date with the embedded tern
// migrations. Migrations are versioned SQL files in internal/db/migrations.
// A schema change is a new file, never an edit to an applied one.
//
// Installations that predate versioned migrations (the schema exists but the
// version table does not) are baselined automatically: the current schema is
// stamped as migration 1 instead of being re-applied. This keeps existing
// deployments zero-touch when upgrading to this release.
//
// A database can also be ahead of the migrations on disk when the migration
// history was squashed into a new base (see the note in 001_base.sql). That
// is stamped down to the newest available migration instead of failing.
func (c *Connection) migrate(ctx context.Context) error {
	conn, err := c.AdminPool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring migration connection: %w", err)
	}
	defer conn.Release()

	// The version table must be checked before creating the migrator: tern's
	// NewMigrator creates it eagerly, which would mask pre-versioned installs.
	tableExists, err := versionTableExists(ctx, conn.Conn(), migrationsVersionTable)
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
			// Same shape as tern's own version table (single row, version 1)
			// so subsequent boots migrate normally.
			if _, err := conn.Exec(ctx, fmt.Sprintf(`
				create table if not exists %s(version int4 not null primary key);
				insert into %s(version) select %d where 0=(select count(*) from %s);
			`, migrationsVersionTable, migrationsVersionTable, baseMigrationVersion, migrationsVersionTable)); err != nil {
				return fmt.Errorf("baselining existing schema: %w", err)
			}
			return nil
		}
	}

	m, err := migrate.NewMigrator(ctx, conn.Conn(), migrationsVersionTable)
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

	// Squashed history. The database is ahead of the migrations on disk, so
	// the old files were replaced by a new base. tern would refuse with
	// BadVersionError. Instead stamp down to the newest available migration,
	// like `tern override-version`.
	//
	// NOTE. The version table is a single integer, so this cannot tell a
	// deliberate squash from an accidentally deleted migration. Both look
	// identical here. Verify the deletion was intentional before booting.
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
