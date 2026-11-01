//go:build integration

package db_test

import (
	"testing"
	"time"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

func TestEmailChangeTokens(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	q := db.New(pinnedConn(t, c, f.ws))
	ctx := t.Context()
	id := uuid.NewV7().String()
	oldEmail, newEmail := id+"@old.test", id+"@new.test"
	_, err := q.CreateUserWithID(ctx, &db.CreateUserWithIDParams{
		ID: id, Email: oldEmail, Name: "u", Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
	})
	require.NoError(t, err, "create user")
	stale, confirm, revert := crypto.HashedToken(id+"-stale"), crypto.HashedToken(id+"-confirm"),
		crypto.HashedToken(id+"-revert")
	put := func(hash crypto.HashedToken, purpose, email string) {
		t.Helper()
		require.NoError(t, q.PutToken(ctx, &db.PutTokenParams{
			TokenHash: hash, UserID: &id, Purpose: purpose,
			ExpiresAt: time.Now().Add(time.Hour), Email: &email,
		}), "put %s token", purpose)
	}
	consume := func(hash crypto.HashedToken, purpose string) (*db.ConsumeEmailTokenRow, error) {
		return q.ConsumeEmailToken(ctx, &db.ConsumeEmailTokenParams{TokenHash: hash, Purpose: purpose})
	}
	pendingParams := &db.GetPendingTokenEmailParams{UserID: &id, Purpose: "email_change"}

	// A second request replaces the first, a stale link confirms nothing.
	put(stale, "email_change", id+"@typo.test")
	require.NoError(t, q.DeleteUserTokens(
		ctx,
		&db.DeleteUserTokensParams{UserID: &id, Purpose: "email_change"},
	), "delete tokens")
	put(confirm, "email_change", newEmail)
	put(revert, "email_revert", oldEmail)

	pending, err := q.GetPendingTokenEmail(ctx, pendingParams)
	require.NoError(t, err, "pending")
	require.Equal(t, newEmail, pending)
	_, err = consume(stale, "email_change")
	require.ErrorIs(t, err, pgx.ErrNoRows, "stale token")
	_, err = consume(confirm, "email_revert")
	require.ErrorIs(t, err, pgx.ErrNoRows, "wrong purpose")

	// Confirm: the token carries the new address and works once.
	row, err := consume(confirm, "email_change")
	require.NoError(t, err, "confirm")
	require.Equal(t, id, row.UserID)
	require.Equal(t, newEmail, row.Email)
	u, err := q.SetUserEmail(ctx, &db.SetUserEmailParams{ID: id, Email: row.Email})
	require.NoError(t, err, "set email")
	require.Equal(t, newEmail, u.Email)
	_, err = consume(confirm, "email_change")
	require.ErrorIs(t, err, pgx.ErrNoRows, "second confirm")
	_, err = q.GetPendingTokenEmail(ctx, pendingParams)
	require.ErrorIs(t, err, pgx.ErrNoRows, "pending after confirm")

	// Revert: the token still knows the old address after the swap.
	row, err = consume(revert, "email_revert")
	require.NoError(t, err, "revert")
	require.Equal(t, oldEmail, row.Email)
	u, err = q.SetUserEmail(ctx, &db.SetUserEmailParams{ID: id, Email: row.Email})
	require.NoError(t, err, "restore email")
	require.Equal(t, oldEmail, u.Email)

	// An address somebody else in the workspace holds is refused.
	other := uuid.NewV7().String()
	_, err = q.CreateUserWithID(ctx, &db.CreateUserWithIDParams{
		ID: other, Email: newEmail, Name: "o", Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
	})
	require.NoError(t, err, "create other user")
	_, err = q.SetUserEmail(ctx, &db.SetUserEmailParams{ID: id, Email: newEmail})
	require.Error(t, err, "taking a used address succeeded")
}
