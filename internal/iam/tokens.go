package iam

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// One-time token purposes.
const (
	TokenVerifyEmail   = "verify"
	TokenPasswordReset = "reset"
	resendCooldown     = 5 * time.Minute
)

// IssueToken creates a one-time token for the user and returns the raw
// token. The raw value crosses the wire exactly once; only its hash is
// stored, and consumption is a single atomic delete.
func (s *Service) IssueToken(
	ctx context.Context,
	userID, purpose string,
	ttl time.Duration,
) (string, error) {
	raw, tokenHash, err := crypto.NewSecret()
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	err = s.sys.PutToken(ctx, &db.PutTokenParams{
		TokenHash: tokenHash,
		UserID:    userID,
		Purpose:   purpose,
		ExpiresAt: s.now().Add(ttl),
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// ConsumeToken atomically deletes a token of the given purpose and returns
// its owner. Unknown, spent, expired, and wrong-purpose tokens all return
// ErrInvalidToken. A wrong-purpose token stays unspent.
func (s *Service) ConsumeToken(ctx context.Context, raw, purpose string) (string, error) {
	tokenHash, err := crypto.HashToken(raw)
	if err != nil {
		return "", ErrInvalidToken
	}
	userID, err := s.sys.ConsumeToken(ctx, &db.ConsumeTokenParams{TokenHash: tokenHash, Purpose: purpose})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidToken
	}
	return userID, err
}

// DeleteExpiredTokens prunes expired one-time tokens and reports how many
// went. It backs a hygiene job.
func (s *Service) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	return s.sys.DeleteExpiredTokens(ctx, s.now())
}

// HasRecentToken reports whether a token for the user and purpose was
// issued within the window, so hosts can rate-limit resend emails.
func (s *Service) HasRecentToken(
	ctx context.Context,
	userID, purpose string,
) (bool, error) {
	return s.sys.HasRecentToken(ctx, &db.HasRecentTokenParams{
		UserID:  userID,
		Purpose: purpose,
		Since:   s.now().Add(-resendCooldown),
	})
}
