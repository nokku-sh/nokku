package db

import (
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

func IsForeignKeyViolation(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == pgerrcode.ForeignKeyViolation
}

// IsUniqueViolation also matches exclusion constraint violations.
func IsUniqueViolation(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && (pgErr.Code == pgerrcode.UniqueViolation ||
		pgErr.Code == pgerrcode.ExclusionViolation)
}
