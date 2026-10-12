package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsUniqueViolation(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"unique":      {&pgconn.PgError{Code: pgerrcode.UniqueViolation}, true},
		"exclusion":   {&pgconn.PgError{Code: pgerrcode.ExclusionViolation}, true},
		"wrapped":     {fmt.Errorf("insert target: %w", &pgconn.PgError{Code: pgerrcode.UniqueViolation}), true},
		"foreign key": {&pgconn.PgError{Code: pgerrcode.ForeignKeyViolation}, false},
		"plain":       {errors.New("connection reset"), false},
		"nil":         {nil, false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := IsUniqueViolation(tc.err); got != tc.want {
				t.Errorf("IsUniqueViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
