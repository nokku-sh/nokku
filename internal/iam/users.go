package iam

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
	emailverify "github.com/nokku-sh/nokku/internal/email"
)

// Register creates a user with the given email and password. The email is
// normalized and validated (ErrEmailRejected); a duplicate returns
// ErrEmailTaken. The account starts unverified and can only log in after
// confirming the emailed link.
func (s *Service) Register(ctx context.Context, email, name, pw string) (*db.User, error) {
	email = normalizeEmail(email)
	if err := emailverify.Verify(email); err != nil {
		return nil, ErrEmailRejected
	}
	u, err := s.q.CreateUser(ctx, &db.CreateUserParams{Email: email, Name: name})
	if err != nil {
		return nil, mapUserError(err)
	}
	if err := s.Password.store(ctx, u.ID, pw); err != nil {
		return nil, err
	}
	s.record(
		ctx,
		Event{
			Action: ActionUserCreated,
			Kind:   KindUser,
			Method: MethodPassword,
			UserID: u.ID,
			Email:  u.Email,
		},
	)
	return u, nil
}

// GetUser returns the user by ID, or ErrNotFound.
func (s *Service) GetUser(ctx context.Context) (*db.User, error) {
	u, err := s.q.GetUser(ctx, UserIDFromContext(ctx))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

func (s *Service) GetUserByID(ctx context.Context, userID string) (*db.User, error) {
	u, err := s.q.GetUser(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// GetUserByEmail returns the user by normalized email, or ErrNotFound.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*db.User, error) {
	u, err := s.q.GetUserByEmail(ctx, normalizeEmail(email))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// UpdateUser applies the patch and returns the updated user.
func (s *Service) UpdateUser(ctx context.Context, p db.UpdateUserParams) (*db.User, error) {
	userID := UserIDFromContext(ctx)
	if userID == "" && p.ID != "" {
		userID = p.ID
	}
	u, err := s.q.UpdateUser(ctx, &db.UpdateUserParams{
		ID:                   userID,
		Name:                 p.Name,
		Picture:              p.Picture,
		Active:               p.Active,
		DisablePasswordReset: p.DisablePasswordReset,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// DeleteUser removes the user and every dependent row: credentials,
// sessions, one-time tokens, memberships, and owned workspaces, through the
// schema's ON DELETE CASCADE. A deprovisioned account must not leave a live
// session or a stored credential behind.
func (s *Service) DeleteUser(ctx context.Context) error {
	userID := UserIDFromContext(ctx)
	u, err := s.GetUser(ctx)
	if err != nil {
		return err
	}
	if err := s.q.DeleteUser(ctx, userID); err != nil {
		return err
	}
	s.record(ctx, Event{Action: ActionUserDeleted, Kind: KindUser, UserID: userID, Email: u.Email})
	return nil
}

// DeleteUnverifiedUsers removes accounts whose email was never verified
// before cutoff and reports how many went. It backs a hygiene job; the grace
// period is the caller's policy.
func (s *Service) DeleteUnverifiedUsers(ctx context.Context, cutoff time.Time) (int64, error) {
	return s.q.DeleteUnverifiedUsers(ctx, cutoff)
}

// VerifyUserEmail marks the account's email as verified.
func (s *Service) VerifyUserEmail(ctx context.Context, userID string) error {
	return s.q.VerifyUserEmail(ctx, userID)
}
