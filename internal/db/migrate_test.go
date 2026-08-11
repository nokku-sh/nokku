package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The tests below exercise the tern-based migrator against a real, fully
// migrated database. They are skipped when the development PostgreSQL
// container (compose.test.yml) is not running.

// migrateTestDB creates a scratch database and returns a connection to it
// plus its name; both are cleaned up when the test finishes.
func migrateTestDB(t *testing.T) (*pgx.Conn, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	admin, err := pgx.Connect(
		ctx,
		"postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
	)
	if err != nil {
		t.Skipf("test database not available (%v); start compose.test.yml", err)
	}
	dbName := fmt.Sprintf("nokku_migrate_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	_ = admin.Close(ctx)

	conn, err := pgx.Connect(
		ctx,
		fmt.Sprintf("postgres://postgres:postgres@localhost:5432/%s?sslmode=disable", dbName),
	)
	if err != nil {
		t.Fatalf("connecting to test database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = conn.Close(cleanupCtx)

		admin2, err := pgx.Connect(
			cleanupCtx,
			"postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
		)
		if err == nil {
			defer admin2.Close(cleanupCtx)
			_, _ = admin2.Exec(cleanupCtx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		}
	})
	return conn, dbName
}

// migrateAppConnection opens the application connection against the scratch
// database, running the boot-time migration sequence.
func migrateAppConnection(t *testing.T, dbName string) *Connection {
	t.Helper()
	t.Setenv("NOKKU_DB_HOST", "localhost")
	t.Setenv("NOKKU_DB_PORT", "5432")
	t.Setenv("NOKKU_DB_NAME", dbName)
	t.Setenv("NOKKU_DB_USER", "postgres")
	t.Setenv("NOKKU_DB_PASSWORD", "postgres")
	conn, err := NewConnection(context.Background())
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	if conn.Pool != nil {
		t.Cleanup(conn.Pool.Close)
	}
	return conn
}

// TestMigrate_FreshDatabase migrates an empty database and verifies the
// squashed base applied end to end: version table at 1, tenant tables, the
// audit schema (previously applied by the audit package) and RLS in place.
func TestMigrate_FreshDatabase(t *testing.T) {
	admin, dbName := migrateTestDB(t)
	ctx := context.Background()

	conn := migrateAppConnection(t, dbName)

	var version int
	if err := conn.AdminPool.QueryRow(ctx, "SELECT version FROM public.schema_migrations").
		Scan(&version); err != nil {
		t.Fatalf("reading version: %v", err)
	}
	if version != baseMigrationVersion {
		t.Errorf("version = %d, want %d", version, baseMigrationVersion)
	}

	for _, obj := range []string{
		"public.users",
		"public.workspaces",
		"audit.audit_logs",
	} {
		var exists bool
		if err := conn.AdminPool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", obj).
			Scan(&exists); err != nil {
			t.Fatalf("checking %s: %v", obj, err)
		}
		if !exists {
			t.Errorf("%s missing after migration", obj)
		}
	}

	var rls bool
	if err := conn.AdminPool.QueryRow(ctx, `
		SELECT count(*) > 0 FROM pg_policies WHERE schemaname = 'public' AND policyname = 'tenant_isolation'
	`).Scan(&rls); err != nil {
		t.Fatalf("checking RLS: %v", err)
	}
	if !rls {
		t.Error("tenant_isolation policies missing after migration")
	}

	// Clean up the cluster-role grants before the scratch database is dropped.
	if _, err := admin.Exec(ctx, "DROP OWNED BY nokku_app, nokku_system"); err != nil {
		t.Fatalf("cleaning grants: %v", err)
	}
}

// TestMigrate_BaselinesExistingSchema simulates an install that predates
// versioned migrations: schema present, no version table. The migrator must
// stamp migration 1 instead of re-applying the base (whose DDL is not fully
// idempotent).
func TestMigrate_BaselinesExistingSchema(t *testing.T) {
	admin, dbName := migrateTestDB(t)
	ctx := context.Background()

	if _, err := admin.Exec(ctx, `
		CREATE EXTENSION IF NOT EXISTS pgcrypto;
		CREATE TABLE roles (
			name TEXT PRIMARY KEY,
			description TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE users (
			id UUID PRIMARY KEY DEFAULT uuidv7(),
			name TEXT NOT NULL,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		INSERT INTO users (name, username, email) VALUES ('legacy', 'legacy', 'legacy@example.com');
	`); err != nil {
		t.Fatalf("simulating legacy schema: %v", err)
	}

	conn := migrateAppConnection(t, dbName)

	var version int
	if err := conn.AdminPool.QueryRow(ctx, "SELECT version FROM public.schema_migrations").
		Scan(&version); err != nil {
		t.Fatalf("reading version: %v", err)
	}
	if version != baseMigrationVersion {
		t.Errorf("version = %d, want %d", version, baseMigrationVersion)
	}

	// The baseline must not have re-applied the base migration: the legacy
	// row survives and the audit schema (only created by migration 1) is
	// absent, exactly as on the pre-migration install.
	var n int
	if err := conn.AdminPool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil {
		t.Fatalf("counting users: %v", err)
	}
	if n != 1 {
		t.Errorf("users = %d, want 1 (base migration must not re-run)", n)
	}
	var auditExists bool
	if err := conn.AdminPool.QueryRow(ctx, "SELECT to_regclass('audit.audit_logs') IS NOT NULL").
		Scan(&auditExists); err != nil {
		t.Fatalf("checking audit schema: %v", err)
	}
	if auditExists {
		t.Error("audit schema present after baseline, base migration must not run")
	}

	// Follow-up boot: with the version table present and version 1 stamped,
	// a fresh connection must be a no-op.
	migrateAppConnection(t, dbName)

	if _, err := admin.Exec(ctx, "DROP OWNED BY nokku_app, nokku_system"); err != nil {
		t.Fatalf("cleaning grants: %v", err)
	}
}

// TestMigrate_SquashedHistory simulates a database whose migration history
// was squashed: it sits at version 3 while only 001_base.sql remains on
// disk. The migrator must stamp down to the base instead of failing with
// tern's BadVersionError, and must not run any down migrations.
func TestMigrate_SquashedHistory(t *testing.T) {
	admin, dbName := migrateTestDB(t)
	ctx := context.Background()

	if _, err := admin.Exec(ctx, `
		CREATE EXTENSION IF NOT EXISTS pgcrypto;
		CREATE TABLE roles (
			name TEXT PRIMARY KEY,
			description TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE users (
			id UUID PRIMARY KEY DEFAULT uuidv7(),
			name TEXT NOT NULL,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		INSERT INTO users (name, username, email) VALUES ('legacy', 'legacy', 'legacy@example.com');
		CREATE TABLE public.schema_migrations(version int4 not null primary key);
		INSERT INTO public.schema_migrations(version) VALUES (3);
	`); err != nil {
		t.Fatalf("simulating squashed history: %v", err)
	}

	conn := migrateAppConnection(t, dbName)

	var version int
	if err := conn.AdminPool.QueryRow(ctx, "SELECT version FROM public.schema_migrations").
		Scan(&version); err != nil {
		t.Fatalf("reading version: %v", err)
	}
	if version != baseMigrationVersion {
		t.Errorf("version = %d, want %d", version, baseMigrationVersion)
	}

	// The legacy row survives: the stamp must not have applied or rolled
	// back anything.
	var n int
	if err := conn.AdminPool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil {
		t.Fatalf("counting users: %v", err)
	}
	if n != 1 {
		t.Errorf("users = %d, want 1 (no migration may run)", n)
	}

	if _, err := admin.Exec(ctx, "DROP OWNED BY nokku_app, nokku_system"); err != nil {
		t.Fatalf("cleaning grants: %v", err)
	}
}
