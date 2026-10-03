// Package testdb gives each test binary its own fresh database on the
// compose.test.yml Postgres.
package testdb

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

// Setup does nothing without a reachable Postgres, so database tests skip.
// In CI that is an error.
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
		// CI must not pass by skipping every database test.
		if os.Getenv("CI") != "" {
			panic(fmt.Sprintf("testdb: no Postgres in CI: %v", err))
		}
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	ident := pgx.Identifier{database}.Sanitize()
	_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
	_, _ = conn.Exec(ctx, "CREATE DATABASE "+ident)
}
