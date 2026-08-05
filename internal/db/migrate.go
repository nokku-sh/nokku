package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stripe/pg-schema-diff/pkg/diff"
	"github.com/stripe/pg-schema-diff/pkg/tempdb"
)

// NOTE: This is a 2-step process due to a bug in the pg-schema-diff library
// See https://github.com/stripe/pg-schema-diff/issues/266

//go:embed schema
var schemaFS embed.FS

func (c *Connection) Migrate(ctx context.Context) error {
	slog.Debug("migrating database schema")

	schemaDDL, rlsDDL, err := loadSQLFiles(schemaFS)
	if err != nil {
		return fmt.Errorf("loading schema files: %w", err)
	}

	// Phase 1: apply tables, functions, etc.
	// Note: the "audit" schema is excluded — the audit package manages
	// its own schema and partitions independently.
	if err := c.applyDDL(ctx, schemaDDL); err != nil {
		return fmt.Errorf("applying schema: %w", err)
	}

	if len(rlsDDL) > 0 {
		slog.Debug("migrating RLS policies")

		// Send full DDL (tables + RLS) so the temp database has all tables
		// when CREATE POLICY statements are applied. Only policy changes will
		// materialize in the plan — tables are already in place from Phase 1.
		fullDDL := make([]string, 0, len(schemaDDL)+len(rlsDDL))
		fullDDL = append(fullDDL, schemaDDL...)
		fullDDL = append(fullDDL, rlsDDL...)

		if err := c.applyDDL(ctx, fullDDL); err != nil {
			return fmt.Errorf("applying RLS policies: %w", err)
		}
	}

	return nil
}

func (c *Connection) applyDDL(ctx context.Context, ddl []string) error {
	if len(ddl) == 0 {
		return nil
	}

	connConfig := c.Pool.Config().ConnConfig.Copy()

	tempDBFactory, err := tempdb.NewOnInstanceFactory(
		ctx,
		func(_ context.Context, dbName string) (*sql.DB, error) {
			cfg := connConfig.Copy()
			cfg.Database = dbName
			return stdlib.OpenDB(*cfg), nil
		},
	)
	if err != nil {
		return fmt.Errorf("creating temp db factory: %w", err)
	}
	defer func() { _ = tempDBFactory.Close() }()

	db := stdlib.OpenDBFromPool(c.Pool)
	defer func() { _ = db.Close() }()

	plan, err := diff.Generate(
		ctx,
		diff.DBSchemaSource(db),
		diff.DDLSchemaSource(ddl),
		diff.WithTempDbFactory(tempDBFactory),
		diff.WithDoNotValidatePlan(),
		diff.WithExcludeSchemas("audit"),
	)
	if err != nil {
		return fmt.Errorf("generating migration plan: %w", err)
	}

	if len(plan.Statements) == 0 {
		return nil
	}

	conn, err := c.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection: %w", err)
	}
	defer conn.Release()

	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext('migration'))").
		Scan(&locked); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("another migration is already in progress")
	}
	defer func() {
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtext('migration'))")
	}()

	for _, stmt := range plan.Statements {
		if _, err := conn.Exec(
			ctx,
			fmt.Sprintf("SET SESSION statement_timeout = '%dms'", stmt.Timeout.Milliseconds()),
		); err != nil {
			return fmt.Errorf("setting statement timeout: %w", err)
		}
		if _, err := conn.Exec(
			ctx,
			fmt.Sprintf("SET SESSION lock_timeout = '%dms'", stmt.LockTimeout.Milliseconds()),
		); err != nil {
			return fmt.Errorf("setting lock timeout: %w", err)
		}
		if _, err := conn.Exec(ctx, stmt.ToSQL()); err != nil {
			return fmt.Errorf("migration failed (db may be dirty): %s: %w", stmt.ToSQL(), err)
		}
	}

	return nil
}

func loadSQLFiles(fsys embed.FS) (schemaDDL, rlsDDL []string, _ error) {
	err := fs.WalkDir(fsys, "schema", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(filePath, ".sql") {
			return nil
		}

		content, err := fsys.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		if strings.HasPrefix(filePath, "schema/rls/") {
			rlsDDL = append(rlsDDL, string(content))
		} else {
			schemaDDL = append(schemaDDL, string(content))
		}
		return nil
	})

	return schemaDDL, rlsDDL, err
}
