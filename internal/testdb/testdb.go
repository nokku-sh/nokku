// Package testdb gives each test binary a fresh database of its own on the
// compose.test.yml Postgres. Tests never touch the dev database, never see
// each other's rows, and always run the current schema.
package testdb

import (
	"context"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

// Setup recreates nokku_test_<name> and points PGDATABASE at it. Call it
// from TestMain. Without a reachable Postgres it does nothing and the
// database tests skip.
func Setup(name string) {
	// The defaults db.NewConnection applies, so both reach the same server.
	for key, fallback := range map[string]string{
		"PGHOST":     "localhost",
		"PGPORT":     "5432",
		"PGUSER":     "postgres",
		"PGPASSWORD": "postgres",
		"PGSSLMODE":  "disable",
	} {
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, fallback)
		}
	}
	database := "nokku_test_" + name
	_ = os.Setenv("PGDATABASE", database)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return
	}
	cfg.Database = "postgres"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	ident := pgx.Identifier{database}.Sanitize()
	_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
	_, _ = conn.Exec(ctx, "CREATE DATABASE "+ident)
}
