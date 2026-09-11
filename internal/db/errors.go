package db

import (
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// IsUniqueViolation reports whether err is a Postgres unique or exclusion
// constraint violation. Callers treat it as a retryable collision rather than
// a failure: generated names, concurrent inserts of the same row.
func IsUniqueViolation(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && (pgErr.Code == pgerrcode.UniqueViolation ||
		pgErr.Code == pgerrcode.ExclusionViolation)
}
