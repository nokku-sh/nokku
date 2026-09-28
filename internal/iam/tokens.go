package iam

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

const (
	TokenVerifyEmail   = "verify"
	TokenPasswordReset = "reset"
	resendCooldown     = 5 * time.Minute
)

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

// ConsumeToken leaves a wrong-purpose token unspent.
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

func (s *Service) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	return s.sys.DeleteExpiredTokens(ctx, s.now())
}

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
