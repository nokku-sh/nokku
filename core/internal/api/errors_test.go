package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

func TestToConnectErrorGroups(t *testing.T) {
	pg := func(code string) error { return fmt.Errorf("query: %w", &pgconn.PgError{Code: code}) }
	tests := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"no rows", fmt.Errorf("get: %w", pgx.ErrNoRows), connect.CodeNotFound},
		{"unique", pg(pgerrcode.UniqueViolation), connect.CodeAlreadyExists},
		{"exclusion", pg(pgerrcode.ExclusionViolation), connect.CodeAlreadyExists},
		{"foreign key", pg(pgerrcode.ForeignKeyViolation), connect.CodeFailedPrecondition},
		{"restrict", pg(pgerrcode.RestrictViolation), connect.CodeFailedPrecondition},
		{"not null", pg(pgerrcode.NotNullViolation), connect.CodeInvalidArgument},
		{"check", pg(pgerrcode.CheckViolation), connect.CodeInvalidArgument},
		{"too long", pg(pgerrcode.StringDataRightTruncationDataException), connect.CodeInvalidArgument},
		{"bad uuid", pg(pgerrcode.InvalidTextRepresentation), connect.CodeInvalidArgument},
		{"serialization", pg(pgerrcode.SerializationFailure), connect.CodeAborted},
		{"deadlock", pg(pgerrcode.DeadlockDetected), connect.CodeAborted},
		{"canceled", fmt.Errorf("tx: %w", context.Canceled), connect.CodeCanceled},
		{"query canceled", pg(pgerrcode.QueryCanceled), connect.CodeCanceled},
		{"deadline", context.DeadlineExceeded, connect.CodeDeadlineExceeded},
		{"no permission", db.ErrPermissionDenied, connect.CodePermissionDenied},
		{"connect error passes", connect.NewError(connect.CodeNotFound, "gone"), connect.CodeNotFound},
		{"unknown postgres code", pg(pgerrcode.DiskFull), connect.CodeInternal},
		{"plain error", errors.New("stripe said no"), connect.CodeInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, connect.CodeOf(toConnectError(t.Context(), tt.err)))
		})
	}
}

// A seat refusal joins the plan's connect error. The workspace's answer wins.
func TestToConnectErrorIAMRefusals(t *testing.T) {
	plan := connect.NewError(connect.CodeResourceExhausted, "your plan includes 5 members; upgrade to add more")
	tests := []struct {
		err  error
		want error
	}{
		{errors.Join(iam.ErrSeatLimit, plan), errSeatLimit},
		{fmt.Errorf("tx: %w", iam.ErrSSORequired), errSSORequired},
		{iam.ErrInviteSpent, errInviteInvalid},
	}
	for _, tt := range tests {
		assert.Same(t, tt.want, toConnectError(t.Context(), tt.err), "%v", tt.err)
	}
}

// The mapper logs the cause once, with what the client never sees.
func TestInternalErrorIsLoggedOnce(t *testing.T) {
	var out bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	err := toConnectError(t.Context(), fmt.Errorf("listing: %w", &pgconn.PgError{Code: pgerrcode.DiskFull}))

	assert.Equal(t, errInternal, err)
	assert.Equal(t, 1, strings.Count(out.String(), "internal error"))
	assert.Contains(t, out.String(), "pg_code="+pgerrcode.DiskFull)
	assert.NotContains(t, err.Error(), "listing", "the cause reached the client")

	out.Reset()
	toConnectError(t.Context(), &pgconn.PgError{Code: pgerrcode.UniqueViolation})
	assert.Empty(t, out.String(), "an error a client can act on is not logged")
}
