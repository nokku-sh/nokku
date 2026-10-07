package iam

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	emailverify "github.com/nokku-sh/nokku/internal/email"
)

const (
	tokenEmailChange = "email_change"
	tokenEmailRevert = "email_revert"

	EmailChangeTTL = time.Hour
	// EmailRevertTTL outlives the change, so the old inbox can undo it later.
	EmailRevertTTL = 7 * 24 * time.Hour
)

var ErrSameEmail = errors.New("iam: email unchanged")

// RequestEmailChange replaces any pending change of u. confirm goes to the
// new address, cancel to the current one. The account keeps its address
// until confirm is used. An account an identity provider manages keeps the
// address the provider gave it.
func (s *Service) RequestEmailChange(
	ctx context.Context,
	u *db.User,
	newEmail string,
) (confirm, cancel string, err error) {
	newEmail = normalizeEmail(newEmail)
	if newEmail == u.Email {
		return "", "", ErrSameEmail
	}
	if err = emailverify.Verify(ctx, newEmail, s.strict); err != nil {
		return "", "", ErrEmailRejected
	}
	err = s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		creds, err := q.ListUserCredentials(ctx, u.ID)
		if err != nil {
			return err
		}
		for _, c := range creds {
			if c.Type == string(MethodOIDC) || c.Type == string(MethodSCIM) {
				return ErrManagedAccount
			}
		}
		if _, err = q.GetUserByEmail(ctx, newEmail); err == nil {
			return ErrEmailTaken
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
			UserID: &u.ID, Purpose: tokenEmailChange,
		}); err != nil {
			return err
		}
		// The cancel token goes first, a change must never exist without its undo.
		if cancel, err = s.putEmailToken(ctx, q, u.ID, tokenEmailRevert, u.Email, EmailRevertTTL); err != nil {
			return err
		}
		confirm, err = s.putEmailToken(ctx, q, u.ID, tokenEmailChange, newEmail, EmailChangeTTL)
		return err
	})
	if err != nil {
		return "", "", err
	}
	return confirm, cancel, nil
}

func (s *Service) putEmailToken(
	ctx context.Context,
	q *db.Queries,
	userID, purpose, email string,
	ttl time.Duration,
) (string, error) {
	raw, hash := crypto.NewSecret()
	return raw, q.PutToken(ctx, &db.PutTokenParams{
		TokenHash: hash,
		UserID:    &userID,
		Purpose:   purpose,
		ExpiresAt: s.now().Add(ttl),
		Email:     &email,
	})
}

// DropEmailChange forgets the pending change of userID.
func (s *Service) DropEmailChange(ctx context.Context, userID string) error {
	return s.conn.Tenant().DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
		UserID: &userID, Purpose: tokenEmailChange,
	})
}

// PendingEmail returns the address a change is waiting on, or "".
func (s *Service) PendingEmail(ctx context.Context, userID string) string {
	email, err := s.conn.Tenant().GetPendingTokenEmail(ctx, &db.GetPendingTokenEmailParams{
		UserID: &userID, Purpose: tokenEmailChange,
	})
	if err != nil {
		return ""
	}
	return email
}

// ConfirmEmailChange switches the account to the address the token carries.
func (s *Service) ConfirmEmailChange(ctx context.Context, raw string) error {
	var u *db.User
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		row, err := consumeEmailToken(ctx, q, raw, tokenEmailChange)
		if err != nil {
			return err
		}
		u, err = q.SetUserEmail(ctx, &db.SetUserEmailParams{ID: row.UserID, Email: row.Email})
		return mapUserError(err)
	})
	if err != nil {
		return err
	}
	s.record(ctx, event{Action: actionEmailChanged, Kind: actor.KindUser, UserID: u.ID, Email: u.Email})
	return nil
}

// CancelEmailChange drops a pending change. When the change already
// happened it puts the old address back and signs the account out
// everywhere, since whoever changed it held a session.
func (s *Service) CancelEmailChange(ctx context.Context, raw string) error {
	var u *db.User
	reverted := false
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		row, err := consumeEmailToken(ctx, q, raw, tokenEmailRevert)
		if err != nil {
			return err
		}
		if err := q.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
			UserID: &row.UserID, Purpose: tokenEmailChange,
		}); err != nil {
			return err
		}
		if u, err = q.GetUser(ctx, row.UserID); err != nil {
			return err
		}
		if u.Email == row.Email {
			return nil
		}
		if u, err = q.SetUserEmail(
			ctx,
			&db.SetUserEmailParams{ID: u.ID, Email: row.Email},
		); err != nil {
			return mapUserError(err)
		}
		reverted = true
		_, err = q.DeleteSubjectSessions(ctx, u.ID)
		return err
	})
	if err != nil || !reverted {
		return err
	}
	s.record(
		ctx,
		event{Action: actionEmailChanged, Kind: actor.KindUser, UserID: u.ID, Email: u.Email, Detail: "reverted"},
	)
	return nil
}

func consumeEmailToken(
	ctx context.Context,
	q *db.Queries,
	raw, purpose string,
) (*db.ConsumeEmailTokenRow, error) {
	hash := crypto.HashToken(raw)
	row, err := q.ConsumeEmailToken(
		ctx,
		&db.ConsumeEmailTokenParams{TokenHash: hash, Purpose: purpose},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidToken
	}
	return row, err
}
