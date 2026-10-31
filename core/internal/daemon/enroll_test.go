package daemon

import (
	"context"
	"errors"
	"strings"
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
	token, _ := crypto.NewToken(crypto.TokenEnroll)
	_, err := Enroll(t.Context(), failingConn{}, EnrollInput{Token: token})
	if err == nil || errors.Is(err, ErrEnrollToken) {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
}

// untouchedConn fails the test when asked, a token that is no enroll token must not get that far.
type untouchedConn struct{ t *testing.T }

func (c untouchedConn) SysTx(context.Context, func(*db.Queries) error) error {
	c.t.Error("the token reached the database")
	return nil
}

func (c untouchedConn) TenantTx(ctx context.Context, fn func(*db.Queries) error) error {
	return c.SysTx(ctx, fn)
}

func TestEnroll_RefusesAWrongTokenWithoutAQuery(t *testing.T) {
	invite, _ := crypto.NewToken(crypto.TokenInvite)
	enroll, _ := crypto.NewToken(crypto.TokenEnroll)
	last := "A"
	if strings.HasSuffix(enroll, last) {
		last = "B"
	}
	for name, token := range map[string]string{
		"an invite":      invite,
		"a typo":         enroll[:len(enroll)-1] + last,
		"the old format": uuid.NewV7().String() + "_" + crypto.RandomString(32),
	} {
		_, err := Enroll(t.Context(), untouchedConn{t}, EnrollInput{Token: token})
		if !errors.Is(err, ErrEnrollToken) {
			t.Errorf("%s: err = %v, want ErrEnrollToken", name, err)
		}
	}
}
