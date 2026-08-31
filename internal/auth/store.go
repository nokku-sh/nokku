package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"

	kagipg "github.com/mizuchilabs/kagi/store/postgres"
)

// OpenStore opens kagi's built-in PostgreSQL store. kagi owns identity: the
// users, credentials, sessions, api_keys, and groups tables live in their own
// "kagi" schema and are migrated by the store itself on Open.
//
// The store connects with the same libpq environment variables as the main
// connection pool and runs its migrations and traffic as the database owner.
// There is no RLS on kagi tables: identity is global by design. nokku reads
// identity through kagi's managers (Service().Users, Service().Credentials),
// never through direct SQL.
func OpenStore(ctx context.Context) (*kagipg.Store, error) {
	dsn := dsnFromEnv()

	return kagipg.Open(ctx, kagipg.Config{
		DSN: dsn,
		Logger: func(format string, args ...any) {
			slog.Info(fmt.Sprintf("kagi store: "+format, args...))
		},
	})
}

// dsnFromEnv builds the kagi store URL from the libpq variables the main
// pool also reads, with the same defaults (see internal/db.NewConnection).
func dsnFromEnv() string {
	host := envOr("PGHOST", "localhost")
	port := envOr("PGPORT", "5432")
	name := envOr("PGDATABASE", "nokku")
	user := envOr("PGUSER", "postgres")
	pass := envOr("PGPASSWORD", "postgres")

	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, pass),
		Host:   host + ":" + port,
		Path:   "/" + name,
	}
	q := url.Values{}
	if ssl := os.Getenv("PGSSLMODE"); ssl != "" {
		q.Set("sslmode", ssl)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
