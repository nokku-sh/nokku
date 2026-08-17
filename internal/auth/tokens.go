package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// TokenPurpose discriminates what a one-time token is for.
type TokenPurpose string

const (
	PurposeVerify TokenPurpose = "verify"
	PurposeReset  TokenPurpose = "reset"
)

// Tokens issues and consumes one-time tokens (email verification, password
// reset). Only the sha256 of a token is stored; the raw token is shown to the
// user once.
type Tokens struct {
	conn *db.Connection
	ttl  time.Duration
}

// NewTokens builds a one-time token issuer. ttl is the default token lifetime.
func NewTokens(conn *db.Connection, ttl time.Duration) *Tokens {
	return &Tokens{conn: conn, ttl: ttl}
}

// Issue mints a one-time token for the user and purpose and returns the raw
// token to hand to the user.
func (t *Tokens) Issue(
	ctx context.Context,
	userID string,
	purpose TokenPurpose,
) (string, error) {
	raw, err := crypto.RandomString(32)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(raw))
	if err := t.conn.Q.CreateOneTimeToken(ctx, &db.CreateOneTimeTokenParams{
		TokenHash: sum[:],
		UserID:    userID,
		Purpose:   string(purpose),
		ExpiresAt: time.Now().Add(t.ttl),
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// Consume validates a one-time token, deletes it, and returns the user and
// purpose it was issued for.
func (t *Tokens) Consume(
	ctx context.Context,
	raw string,
) (userID string, purpose TokenPurpose, err error) {
	if raw == "" {
		return "", "", errors.New("auth: missing token")
	}
	sum := sha256.Sum256([]byte(raw))
	row, err := t.conn.Q.GetOneTimeToken(ctx, sum[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", errors.New("auth: invalid or expired token")
		}
		return "", "", err
	}
	if row.ExpiresAt.Before(time.Now()) {
		_ = t.conn.Q.DeleteOneTimeToken(ctx, sum[:])
		return "", "", errors.New("auth: invalid or expired token")
	}
	if err := t.conn.Q.DeleteOneTimeToken(ctx, sum[:]); err != nil {
		return "", "", err
	}
	return row.UserID, TokenPurpose(row.Purpose), nil
}
