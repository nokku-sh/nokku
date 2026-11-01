package iam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	emailverify "github.com/nokku-sh/nokku/core/internal/email"
)

const (
	tokenLogin     = "login"
	magicLinkTTL   = 15 * time.Minute
	BootstrapTTL   = 24 * time.Hour
	mailTimeout    = 30 * time.Second
	loginVerifyURL = "/login/verify?token="
)

// RequestMagicLink runs detached, so timing never shows if the address exists.
func (s *Service) RequestMagicLink(ctx context.Context, email string) {
	if s.sendMagicLink == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	go func() {
		if err := s.mailLoginLink(ctx, NormalizeEmail(email)); err != nil {
			slog.Warn("sign-in link not made", "error", err)
		}
	}()
}

func (s *Service) mailLoginLink(ctx context.Context, email string) error {
	sendCtx, cancel := context.WithTimeout(ctx, mailTimeout)
	defer cancel()
	var u *db.User
	var link string
	var hash crypto.HashedToken
	err := s.conn.TenantTx(sendCtx, func(q *db.Queries) error {
		found, err := q.GetUserByEmail(sendCtx, email)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		u = found
		if !found.Active {
			return nil
		}
		link, hash, err = s.putLoginToken(sendCtx, q, found.ID, magicLinkTTL)
		return err
	})
	if err != nil {
		return err
	}
	if u == nil {
		s.record(ctx, event{Action: actionLoginDenied, Method: MethodMagicLink, Email: email, Detail: "unknown email"})
		return nil
	}
	if link == "" {
		s.record(
			ctx,
			event{Action: actionLoginDenied, Method: MethodMagicLink, Email: email, Detail: "inactive account"},
		)
		return nil
	}
	if err := s.sendMagicLink(sendCtx, u.ID, u.Email, link, magicLinkTTL); err != nil {
		s.dropUnsent(ctx, hash, err)
	}
	return nil
}

// dropUnsent forgets an unsent link. Only the mail cooldown counts requests.
func (s *Service) dropUnsent(ctx context.Context, hash crypto.HashedToken, cause error) {
	if !errors.Is(cause, emailverify.ErrCooldown) {
		slog.Warn("link not sent", "error", cause)
	}
	if err := s.conn.Tenant().DeleteToken(ctx, hash); err != nil {
		slog.Warn("unsent link not removed", "error", err)
	}
}

func (s *Service) putLoginToken(
	ctx context.Context,
	q *db.Queries,
	userID string,
	ttl time.Duration,
) (string, crypto.HashedToken, error) {
	raw, hash := crypto.NewToken(crypto.TokenLogin)
	err := q.PutToken(ctx, &db.PutTokenParams{
		TokenHash: hash,
		UserID:    &userID,
		Purpose:   tokenLogin,
		ExpiresAt: s.now().Add(ttl),
	})
	if err != nil {
		return "", "", err
	}
	return baseURL(ctx) + loginVerifyURL + raw, hash, nil
}

// IssueBootstrapLink lets the first admin in before any passkey exists.
func (s *Service) IssueBootstrapLink(ctx context.Context, u *db.User) (string, error) {
	var link string
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if err := q.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
			UserID: &u.ID, Purpose: tokenLogin,
		}); err != nil {
			return err
		}
		link, _, err = s.putLoginToken(ctx, q, u.ID, BootstrapTTL)
		return err
	})
	return link, err
}

func (s *Service) ConsumeMagicLink(ctx context.Context, raw string) (*db.User, *http.Cookie, error) {
	hash, ok := crypto.TokenHash(raw, crypto.TokenLogin)
	if !ok {
		return nil, nil, ErrInvalidToken
	}
	var u *db.User
	err := s.conn.TenantTx(ctx, func(q *db.Queries) error {
		userID, err := q.ConsumeToken(ctx, &db.ConsumeTokenParams{TokenHash: hash, Purpose: tokenLogin})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		u, err = q.GetUser(ctx, userID)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	cookie, err := s.completeLogin(ctx, u, MethodMagicLink)
	if err != nil {
		return nil, nil, err
	}
	return u, cookie, nil
}
