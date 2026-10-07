package iam

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	emailverify "github.com/nokku-sh/nokku/internal/email"
)

const (
	tokenLogin     = "login"
	tokenSignup    = "signup"
	magicLinkTTL   = 15 * time.Minute
	bootstrapTTL   = 24 * time.Hour
	resendCooldown = 5 * time.Minute
	loginVerifyURL = "/login/verify?token="
	inviteURL      = "/invite/verify?token="
)

// RequestMagicLink mails a sign-in link to a user of the workspace. It never
// tells the caller whether the address exists.
func (s *Service) RequestMagicLink(ctx context.Context, email string) error {
	if s.SendMagicLink == nil {
		return nil
	}
	email = normalizeEmail(email)
	var u *db.User
	var link string
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		found, err := q.GetUserByEmail(ctx, &db.GetUserByEmailParams{WorkspaceID: ws, Email: email})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !found.Active {
			return nil
		}
		recent, err := q.HasRecentToken(ctx, &db.HasRecentTokenParams{
			WorkspaceID: ws, UserID: &found.ID, Purpose: tokenLogin, Since: s.now().Add(-resendCooldown),
		})
		if err != nil || recent {
			return err
		}
		link, err = s.putLoginToken(ctx, q, ws, found.ID, magicLinkTTL)
		u = found
		return err
	})
	if err != nil {
		return err
	}
	if u == nil {
		s.record(ctx, Event{Action: ActionLoginDenied, Method: MethodMagicLink, Email: email, Detail: "unknown email"})
		return nil
	}
	if link == "" {
		return nil
	}
	if err := s.SendMagicLink(ctx, u, link, magicLinkTTL); err != nil {
		slog.Warn("magic link not sent", "error", err)
	}
	return nil
}

func (s *Service) putLoginToken(
	ctx context.Context,
	q *db.Queries,
	ws, userID string,
	ttl time.Duration,
) (string, error) {
	raw, hash, err := crypto.NewSecret()
	if err != nil {
		return "", err
	}
	err = q.PutToken(ctx, &db.PutTokenParams{
		TokenHash:   hash,
		WorkspaceID: ws,
		UserID:      &userID,
		Purpose:     tokenLogin,
		ExpiresAt:   s.now().Add(ttl),
	})
	if err != nil {
		return "", err
	}
	return baseURL(ctx) + loginVerifyURL + raw, nil
}

// IssueBootstrapLink is how the first admin gets in before any passkey
// exists. It replaces earlier links and lasts a day.
func (s *Service) IssueBootstrapLink(ctx context.Context, u *db.User) (string, error) {
	var link string
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		if err := q.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
			WorkspaceID: ws, UserID: &u.ID, Purpose: tokenLogin,
		}); err != nil {
			return err
		}
		link, err = s.putLoginToken(ctx, q, ws, u.ID, bootstrapTTL)
		return err
	})
	return link, err
}

// RequestSignupLink mails the link that creates an invited account. The
// invite is checked now and spent when the link is used.
func (s *Service) RequestSignupLink(ctx context.Context, invite, email, name string) error {
	if s.SendSignupLink == nil {
		return errors.New("iam: mail is not configured")
	}
	email = normalizeEmail(email)
	if err := emailverify.Verify(ctx, email, s.strict); err != nil {
		return ErrEmailRejected
	}
	name = strings.TrimSpace(name)
	var link string
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		tok, err := lookupInvite(ctx, q, invite)
		if err != nil {
			return err
		}
		if _, err := q.GetUserByEmail(ctx, &db.GetUserByEmailParams{WorkspaceID: ws, Email: email}); err == nil {
			return ErrEmailTaken
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		recent, err := q.HasRecentToken(ctx, &db.HasRecentTokenParams{
			WorkspaceID: ws, Email: &email, Purpose: tokenSignup, Since: s.now().Add(-resendCooldown),
		})
		if err != nil || recent {
			return err
		}
		data, err := json.Marshal(signupData{Name: name, Role: deref(tok.RoleName), InviteID: tok.ID})
		if err != nil {
			return err
		}
		raw, hash, err := crypto.NewSecret()
		if err != nil {
			return err
		}
		if err := q.PutSignupToken(ctx, &db.PutSignupTokenParams{
			TokenHash:   hash,
			WorkspaceID: ws,
			ExpiresAt:   s.now().Add(magicLinkTTL),
			Email:       &email,
			Data:        data,
		}); err != nil {
			return err
		}
		link = baseURL(ctx) + inviteURL + raw
		return nil
	})
	if err != nil || link == "" {
		return err
	}
	if err := s.SendSignupLink(ctx, email, name, link, magicLinkTTL); err != nil {
		slog.Warn("signup link not sent", "error", err)
	}
	return nil
}

// ConsumeMagicLink spends a sign-in or signup link and signs the browser
// in. A signup link creates the account first.
func (s *Service) ConsumeMagicLink(ctx context.Context, raw string) (*db.User, *http.Cookie, error) {
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return nil, nil, ErrInvalidToken
	}
	var u *db.User
	created := false
	err = s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		userID, err := q.ConsumeToken(
			ctx,
			&db.ConsumeTokenParams{WorkspaceID: ws, TokenHash: hash, Purpose: tokenLogin},
		)
		if err == nil {
			u, err = q.GetUser(ctx, &db.GetUserParams{WorkspaceID: ws, ID: userID})
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		row, err := q.ConsumeSignupToken(ctx, &db.ConsumeSignupTokenParams{WorkspaceID: ws, TokenHash: hash})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		var data signupData
		if err := json.Unmarshal(row.Data, &data); err != nil {
			return err
		}
		u, err = s.createUser(ctx, q, db.CreateUserWithIDParams{
			WorkspaceID: ws, Email: row.Email, Name: data.Name, Role: data.Role,
		}, data.InviteID)
		created = err == nil
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if created {
		s.record(ctx, Event{
			Action: ActionUserCreated, Kind: actor.KindUser, Method: MethodMagicLink, UserID: u.ID, Email: u.Email,
		})
	}
	cookie, err := s.completeLogin(ctx, u, MethodMagicLink)
	if err != nil {
		return nil, nil, err
	}
	return u, cookie, nil
}
