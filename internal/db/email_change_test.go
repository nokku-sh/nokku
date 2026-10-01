package db

import (
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
)

func TestEmailChangeTokens(t *testing.T) {
	c := testConnection(t)
	q := c.Sys()
	ctx := t.Context()
	id := uuid.NewV7().String()
	oldEmail, newEmail := id+"@old.test", id+"@new.test"
	if _, err := q.CreateUserWithID(ctx, &CreateUserWithIDParams{ID: id, Email: oldEmail, Name: "u"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	stale, confirm, revert := crypto.HashedToken(id+"-stale"), crypto.HashedToken(id+"-confirm"),
		crypto.HashedToken(id+"-revert")
	put := func(hash crypto.HashedToken, purpose, email string) {
		t.Helper()
		if err := q.PutToken(ctx, &PutTokenParams{
			TokenHash: hash, UserID: id, Purpose: purpose, ExpiresAt: time.Now().Add(time.Hour), Email: &email,
		}); err != nil {
			t.Fatalf("put %s token: %v", purpose, err)
		}
	}

	// Request: a second one replaces the first, so a stale link confirms nothing.
	put(stale, "email_change", id+"@typo.test")
	if err := q.DeleteUserTokens(ctx, &DeleteUserTokensParams{UserID: id, Purpose: "email_change"}); err != nil {
		t.Fatalf("delete tokens: %v", err)
	}
	put(confirm, "email_change", newEmail)
	put(revert, "email_revert", oldEmail)

	pending, err := q.GetPendingTokenEmail(ctx, &GetPendingTokenEmailParams{UserID: id, Purpose: "email_change"})
	if err != nil || pending == nil || *pending != newEmail {
		t.Fatalf("pending = %v, %v, want %s", pending, err, newEmail)
	}
	_, err = q.ConsumeEmailToken(ctx, &ConsumeEmailTokenParams{TokenHash: stale, Purpose: "email_change"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale token: err = %v, want no rows", err)
	}
	_, err = q.ConsumeEmailToken(ctx, &ConsumeEmailTokenParams{TokenHash: confirm, Purpose: "email_revert"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("wrong purpose: err = %v, want no rows", err)
	}

	// Confirm: the token carries the new address and works once.
	row, err := q.ConsumeEmailToken(ctx, &ConsumeEmailTokenParams{TokenHash: confirm, Purpose: "email_change"})
	if err != nil || row.UserID != id || *row.Email != newEmail {
		t.Fatalf("confirm = %+v, %v", row, err)
	}
	u, err := q.SetUserEmail(ctx, &SetUserEmailParams{ID: id, Email: *row.Email})
	if err != nil || u.Email != newEmail || !u.EmailVerified {
		t.Fatalf("set email = %+v, %v", u, err)
	}
	_, err = q.ConsumeEmailToken(ctx, &ConsumeEmailTokenParams{TokenHash: confirm, Purpose: "email_change"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second confirm: err = %v, want no rows", err)
	}
	_, err = q.GetPendingTokenEmail(ctx, &GetPendingTokenEmailParams{UserID: id, Purpose: "email_change"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("pending after confirm: err = %v, want no rows", err)
	}

	// Revert: the token still knows the old address after the swap.
	row, err = q.ConsumeEmailToken(ctx, &ConsumeEmailTokenParams{TokenHash: revert, Purpose: "email_revert"})
	if err != nil || *row.Email != oldEmail {
		t.Fatalf("revert = %+v, %v", row, err)
	}
	if u, err = q.SetUserEmail(ctx, &SetUserEmailParams{ID: id, Email: *row.Email}); err != nil || u.Email != oldEmail {
		t.Fatalf("restore email = %+v, %v", u, err)
	}

	// An address somebody else holds is refused by the unique constraint.
	other := uuid.NewV7().String()
	if _, err = q.CreateUserWithID(ctx, &CreateUserWithIDParams{ID: other, Email: newEmail, Name: "o"}); err != nil {
		t.Fatalf("create other user: %v", err)
	}
	if _, err = q.SetUserEmail(ctx, &SetUserEmailParams{ID: id, Email: newEmail}); err == nil {
		t.Fatal("taking a used address succeeded")
	}
}
