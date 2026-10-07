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
	err = s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		creds, err := q.ListUserCredentials(ctx, &db.ListUserCredentialsParams{WorkspaceID: ws, UserID: u.ID})
		if err != nil {
			return err
		}
		for _, c := range creds {
			if c.Type == string(MethodOIDC) || c.Type == string(MethodSCIM) {
				return ErrManagedAccount
			}
		}
		if _, err = q.GetUserByEmail(ctx, &db.GetUserByEmailParams{WorkspaceID: ws, Email: newEmail}); err == nil {
			return ErrEmailTaken
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
			WorkspaceID: ws, UserID: &u.ID, Purpose: tokenEmailChange,
		}); err != nil {
			return err
		}
		// The cancel token goes first, a change must never exist without its undo.
		if cancel, err = s.putEmailToken(ctx, q, ws, u.ID, tokenEmailRevert, u.Email, EmailRevertTTL); err != nil {
			return err
		}
		confirm, err = s.putEmailToken(ctx, q, ws, u.ID, tokenEmailChange, newEmail, EmailChangeTTL)
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
	ws, userID, purpose, email string,
	ttl time.Duration,
) (string, error) {
	raw, hash, err := crypto.NewSecret()
	if err != nil {
		return "", err
	}
	return raw, q.PutToken(ctx, &db.PutTokenParams{
		TokenHash:   hash,
		WorkspaceID: ws,
		UserID:      &userID,
		Purpose:     purpose,
		ExpiresAt:   s.now().Add(ttl),
		Email:       &email,
	})
}

// DropEmailChange forgets the pending change of userID.
func (s *Service) DropEmailChange(ctx context.Context, userID string) error {
	return s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		return q.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
			WorkspaceID: ws, UserID: &userID, Purpose: tokenEmailChange,
		})
	})
}

// PendingEmail returns the address a change is waiting on, or "".
func (s *Service) PendingEmail(ctx context.Context, userID string) string {
	var email string
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		email, err = q.GetPendingTokenEmail(ctx, &db.GetPendingTokenEmailParams{
			WorkspaceID: ws, UserID: &userID, Purpose: tokenEmailChange,
		})
		return err
	})
	if err != nil {
		return ""
	}
	return email
}

// ConfirmEmailChange switches the account to the address the token carries.
func (s *Service) ConfirmEmailChange(ctx context.Context, raw string) error {
	var u *db.User
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		row, err := consumeEmailToken(ctx, q, ws, raw, tokenEmailChange)
		if err != nil {
			return err
		}
		u, err = q.SetUserEmail(ctx, &db.SetUserEmailParams{WorkspaceID: ws, ID: row.UserID, Email: row.Email})
		return mapUserError(err)
	})
	if err != nil {
		return err
	}
	s.record(ctx, Event{Action: ActionEmailChanged, Kind: actor.KindUser, UserID: u.ID, Email: u.Email})
	return nil
}

// CancelEmailChange drops a pending change. When the change already
// happened it puts the old address back and signs the account out
// everywhere, since whoever changed it held a session.
func (s *Service) CancelEmailChange(ctx context.Context, raw string) error {
	var u *db.User
	reverted := false
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		row, err := consumeEmailToken(ctx, q, ws, raw, tokenEmailRevert)
		if err != nil {
			return err
		}
		if err := q.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{
			WorkspaceID: ws, UserID: &row.UserID, Purpose: tokenEmailChange,
		}); err != nil {
			return err
		}
		if u, err = q.GetUser(ctx, &db.GetUserParams{WorkspaceID: ws, ID: row.UserID}); err != nil {
			return err
		}
		if u.Email == row.Email {
			return nil
		}
		if u, err = q.SetUserEmail(
			ctx,
			&db.SetUserEmailParams{WorkspaceID: ws, ID: u.ID, Email: row.Email},
		); err != nil {
			return mapUserError(err)
		}
		reverted = true
		_, err = q.DeleteSubjectSessions(ctx, &db.DeleteSubjectSessionsParams{WorkspaceID: ws, SubjectID: u.ID})
		return err
	})
	if err != nil || !reverted {
		return err
	}
	s.record(
		ctx,
		Event{Action: ActionEmailChanged, Kind: actor.KindUser, UserID: u.ID, Email: u.Email, Detail: "reverted"},
	)
	return nil
}

func consumeEmailToken(
	ctx context.Context,
	q *db.Queries,
	ws, raw, purpose string,
) (*db.ConsumeEmailTokenRow, error) {
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return nil, ErrInvalidToken
	}
	row, err := q.ConsumeEmailToken(
		ctx,
		&db.ConsumeEmailTokenParams{WorkspaceID: ws, TokenHash: hash, Purpose: purpose},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidToken
	}
	return row, err
}
