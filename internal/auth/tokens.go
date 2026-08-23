package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/tokens"

	"github.com/nokku-sh/nokku/internal/db"
)

// TokenStore adapts nokku's one_time_tokens table to kagi's tokens.Store.
// Only the sha256 of a token is stored; consuming it deletes it, so a token
// can never be replayed.
type TokenStore struct {
	conn *db.Connection
}

// NewTokenStore builds the one-time-token store adapter.
func NewTokenStore(conn *db.Connection) *TokenStore { return &TokenStore{conn: conn} }

var _ tokens.Store = (*TokenStore)(nil)

// PutToken stores the hash, user, purpose, and expiry.
func (s *TokenStore) PutToken(
	ctx context.Context,
	hash []byte,
	userID string,
	purpose tokens.Purpose,
	expiresAt time.Time,
) error {
	return s.conn.Q.CreateOneTimeToken(ctx, &db.CreateOneTimeTokenParams{
		TokenHash: hash,
		UserID:    userID,
		Purpose:   string(purpose),
		ExpiresAt: expiresAt,
	})
}

// ConsumeToken deletes the token and returns the user and purpose it was
// issued for. It deletes atomically so a token can never be spent twice,
// whether by concurrent requests or replay after use.
func (s *TokenStore) ConsumeToken(
	ctx context.Context,
	hash []byte,
) (string, tokens.Purpose, error) {
	row, err := s.conn.Q.ConsumeOneTimeToken(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", kagi.ErrTokenInvalid
		}
		return "", "", err
	}
	return row.UserID, tokens.Purpose(row.Purpose), nil
}
