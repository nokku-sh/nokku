package iam

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/http"
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
		return "", errInvalidToken
	}
	userID, err := s.sys.ConsumeToken(ctx, &db.ConsumeTokenParams{TokenHash: tokenHash, Purpose: purpose})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errInvalidToken
	}
	return userID, err
}

// ConsumeVerifyToken only takes the link in the browser that signed up. Until
// then the account may hold a stranger's password or passkey, and a link
// opened anywhere else must not make those work. Such a link stays unspent.
func (s *Service) ConsumeVerifyToken(ctx context.Context, header http.Header, raw string) (string, error) {
	tokenHash, err := crypto.HashToken(raw)
	if err != nil {
		return "", errInvalidToken
	}
	userID, err := s.sys.GetTokenUser(ctx, &db.GetTokenUserParams{TokenHash: tokenHash, Purpose: TokenVerifyEmail})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errInvalidToken
	}
	if err != nil {
		return "", err
	}
	if !hmac.Equal([]byte(cookieFromHeader(header, signupCookieName)), []byte(s.signupMAC(userID))) {
		return "", ErrOtherBrowser
	}
	return s.ConsumeToken(ctx, raw, TokenVerifyEmail)
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
