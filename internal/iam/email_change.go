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
// until confirm is used.
func (s *Service) RequestEmailChange(
	ctx context.Context,
	u *db.User,
	newEmail string,
) (confirm, cancel string, err error) {
	newEmail = normalizeEmail(newEmail)
	if newEmail == u.Email {
		return "", "", ErrSameEmail
	}
	if err = emailverify.Verify(newEmail, s.strict); err != nil {
		return "", "", ErrEmailRejected
	}
	if _, err = s.sys.GetUserByEmail(ctx, newEmail); err == nil {
		return "", "", ErrEmailTaken
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}

	if err = s.DropEmailChange(ctx, u.ID); err != nil {
		return "", "", err
	}
	// The cancel token goes first, a change must never exist without its undo.
	if cancel, err = s.putEmailToken(ctx, u.ID, tokenEmailRevert, u.Email, EmailRevertTTL); err != nil {
		return "", "", err
	}
	if confirm, err = s.putEmailToken(ctx, u.ID, tokenEmailChange, newEmail, EmailChangeTTL); err != nil {
		return "", "", err
	}
	return confirm, cancel, nil
}

func (s *Service) putEmailToken(ctx context.Context, userID, purpose, email string, ttl time.Duration) (string, error) {
	raw, hash, err := crypto.NewSecret()
	if err != nil {
		return "", err
	}
	return raw, s.sys.PutToken(ctx, &db.PutTokenParams{
		TokenHash: hash,
		UserID:    userID,
		Purpose:   purpose,
		ExpiresAt: s.now().Add(ttl),
		Email:     &email,
	})
}

// DropEmailChange forgets the pending change of userID.
func (s *Service) DropEmailChange(ctx context.Context, userID string) error {
	return s.sys.DeleteUserTokens(ctx, &db.DeleteUserTokensParams{UserID: userID, Purpose: tokenEmailChange})
}

// PendingEmail returns the address a change is waiting on, or "".
func (s *Service) PendingEmail(ctx context.Context, userID string) string {
	email, err := s.sys.GetPendingTokenEmail(
		ctx,
		&db.GetPendingTokenEmailParams{UserID: userID, Purpose: tokenEmailChange},
	)
	if err != nil || email == nil {
		return ""
	}
	return *email
}

// ConfirmEmailChange switches the account to the address the token carries.
func (s *Service) ConfirmEmailChange(ctx context.Context, raw string) error {
	row, err := s.consumeEmailToken(ctx, raw, tokenEmailChange)
	if err != nil {
		return err
	}
	u, err := s.sys.SetUserEmail(ctx, &db.SetUserEmailParams{ID: row.UserID, Email: *row.Email})
	if err != nil {
		return mapUserError(err)
	}
	// A reset link mailed to the old address must not outlive it.
	if err = s.sys.DeleteUserTokens(
		ctx,
		&db.DeleteUserTokensParams{UserID: u.ID, Purpose: TokenPasswordReset},
	); err != nil {
		return err
	}
	s.record(ctx, Event{Action: ActionEmailChanged, Kind: actor.KindUser, UserID: u.ID, Email: u.Email})
	return nil
}

// CancelEmailChange drops a pending change. When the change already
// happened it puts the old address back and signs the account out
// everywhere, since whoever changed it held a session and the password.
func (s *Service) CancelEmailChange(ctx context.Context, raw string) error {
	row, err := s.consumeEmailToken(ctx, raw, tokenEmailRevert)
	if err != nil {
		return err
	}
	if err = s.DropEmailChange(ctx, row.UserID); err != nil {
		return err
	}
	u, err := s.getUserByID(ctx, row.UserID)
	if err != nil {
		return err
	}
	if u.Email == *row.Email {
		return nil
	}
	if u, err = s.sys.SetUserEmail(ctx, &db.SetUserEmailParams{ID: u.ID, Email: *row.Email}); err != nil {
		return mapUserError(err)
	}
	if _, err = s.revokeSubject(ctx, u.ID); err != nil {
		return err
	}
	s.record(
		ctx,
		Event{Action: ActionEmailChanged, Kind: actor.KindUser, UserID: u.ID, Email: u.Email, Detail: "reverted"},
	)
	return nil
}

func (s *Service) consumeEmailToken(ctx context.Context, raw, purpose string) (*db.ConsumeEmailTokenRow, error) {
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return nil, errInvalidToken
	}
	row, err := s.sys.ConsumeEmailToken(ctx, &db.ConsumeEmailTokenParams{TokenHash: hash, Purpose: purpose})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errInvalidToken
	}
	return row, err
}
