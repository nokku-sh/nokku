package daemon

import (
	"context"
	"errors"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type failingConn struct{}

func (failingConn) SysTx(_ context.Context, fn func(*db.Queries) error) error {
	return fn(db.New(failingTx{}))
}

func (c failingConn) TenantTx(ctx context.Context, fn func(*db.Queries) error) error {
	return c.SysTx(ctx, fn)
}

type failingTx struct{ db.DBTX }

func (failingTx) QueryRow(context.Context, string, ...any) pgx.Row { return failingRow{} }

type failingRow struct{}

func (failingRow) Scan(...any) error { return errors.New("connection lost") }

// A database failure is not a verdict on the token.
func TestEnroll_LookupFailureIsNotABadToken(t *testing.T) {
	token := crypto.NewToken(uuid.NewV7().String())
	_, err := Enroll(t.Context(), failingConn{}, EnrollInput{Token: token.Plaintext})
	if err == nil || errors.Is(err, ErrEnrollToken) {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
}
