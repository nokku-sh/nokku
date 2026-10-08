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
	magicLinkTTL   = 15 * time.Minute
	bootstrapTTL   = 24 * time.Hour
	loginVerifyURL = "/login/verify?token="
	inviteURL      = "/invite/verify?token="
)

// RequestMagicLink mails a sign-in link to a user of the workspace. It never
// tells the caller whether the address exists.
func (s *Service) RequestMagicLink(ctx context.Context, email string) error {
	if s.sendMagicLink == nil {
		return nil
	}
	email = normalizeEmail(email)
	var u *db.User
	var link string
	var hash crypto.HashedToken
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		found, err := q.GetUserByEmail(ctx, email)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !found.Active {
			return nil
		}
		link, hash, err = s.putLoginToken(ctx, q, found.ID, magicLinkTTL)
		u = found
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
		return nil
	}
	if err := s.sendMagicLink(ctx, u.ID, u.Email, link, magicLinkTTL.String()); err != nil {
		s.dropUnsent(ctx, hash, err)
	}
	return nil
}

// dropUnsent forgets a link whose mail did not go out. How often a link may
// be asked for is the mail service's cooldown, nothing here counts as well.
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
	raw, hash := crypto.NewSecret()
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

// IssueBootstrapLink is how the first admin gets in before any passkey
// exists. It replaces earlier links and lasts a day.
func (s *Service) IssueBootstrapLink(ctx context.Context, u *db.User) (string, error) {
	var link string
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		if err := q.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
			UserID: &u.ID, Purpose: tokenLogin,
		}); err != nil {
			return err
		}
		link, _, err = s.putLoginToken(ctx, q, u.ID, bootstrapTTL)
		return err
	})
	return link, err
}

// RequestSignupLink mails the link that creates an invited account. The
// invite is checked now and spent when the link is used.
func (s *Service) RequestSignupLink(ctx context.Context, invite, email, name string) error {
	if s.sendSignupLink == nil {
		return errors.New("iam: mail is not configured")
	}
	email = normalizeEmail(email)
	if err := emailverify.Verify(ctx, email, s.strict); err != nil {
		return ErrEmailRejected
	}
	name = strings.TrimSpace(name)
	var link, workspace string
	var hash crypto.HashedToken
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		tok, err := lookupInvite(ctx, q, invite)
		if err != nil {
			return err
		}
		ws, err := q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		workspace = ws.Name
		if _, err := q.GetUserByEmail(ctx, email); err == nil {
			return ErrEmailTaken
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		data, err := json.Marshal(signupData{Name: name, Role: deref(tok.RoleName), InviteID: tok.ID})
		if err != nil {
			return err
		}
		var raw string
		raw, hash = crypto.NewSecret()
		if err := q.PutSignupToken(ctx, &db.PutSignupTokenParams{
			TokenHash: hash,
			ExpiresAt: s.now().Add(magicLinkTTL),
			Email:     &email,
			Data:      data,
		}); err != nil {
			return err
		}
		link = baseURL(ctx) + inviteURL + raw
		return nil
	})
	if err != nil {
		return err
	}
	err = s.sendSignupLink(ctx, email, name, workspace, link, magicLinkTTL.String())
	if err == nil {
		return nil
	}
	s.dropUnsent(ctx, hash, err)
	// On cooldown the link from a moment ago still works, the answer stays.
	if errors.Is(err, emailverify.ErrCooldown) {
		return nil
	}
	return ErrMailNotSent
}

// ConsumeMagicLink spends a sign-in or signup link and signs the browser
// in. A signup link creates the account first.
func (s *Service) ConsumeMagicLink(ctx context.Context, raw string) (*db.User, *http.Cookie, error) {
	hash := crypto.HashToken(raw)
	var u *db.User
	created := false
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		userID, err := q.ConsumeToken(
			ctx,
			&db.ConsumeTokenParams{TokenHash: hash, Purpose: tokenLogin},
		)
		if err == nil {
			u, err = q.GetUser(ctx, userID)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		row, err := q.ConsumeSignupToken(ctx, hash)
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
			Email: row.Email, Name: data.Name, Role: data.Role,
		}, data.InviteID)
		created = err == nil
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if created {
		s.record(ctx, event{
			Action: actionUserCreated, Kind: actor.KindUser, Method: MethodMagicLink, UserID: u.ID, Email: u.Email,
		})
	}
	cookie, err := s.completeLogin(ctx, u, MethodMagicLink)
	if err != nil {
		return nil, nil, err
	}
	return u, cookie, nil
}
