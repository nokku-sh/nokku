package iam

import (
	"context"
	"strings"
	"time"

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
	var u *db.User
	err := s.conn.WithTx(ctx, func(q *db.Queries) (err error) {
		if u, err = q.CreateUser(ctx, &db.CreateUserParams{Email: email, Name: name}); err != nil {
			return err
		}
		return s.Password.store(ctx, q, u.ID, pw)
	})
	if err != nil {
		return nil, mapUserError(err)
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

// GetUser returns the request user, or ErrNotFound.
func (s *Service) GetUser(ctx context.Context) (*db.User, error) {
	var u *db.User
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		u, err = q.GetUser(ctx, UserIDFromContext(ctx))
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

func (s *Service) GetUserByID(ctx context.Context, userID string) (*db.User, error) {
	u, err := s.sys.GetUser(ctx, userID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

// GetUserByEmail returns the user by normalized email, or ErrNotFound.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*db.User, error) {
	u, err := s.sys.GetUserByEmail(ctx, normalizeEmail(email))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

// UpdateUser applies the patch to user p.ID and returns the updated user.
func (s *Service) UpdateUser(ctx context.Context, p db.UpdateUserParams) (*db.User, error) {
	u, err := s.sys.UpdateUser(ctx, &p)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

// UpdateSelf applies the patch to the request user. Active stays untouched:
// nobody reactivates themselves.
func (s *Service) UpdateSelf(ctx context.Context, p db.UpdateUserParams) (*db.User, error) {
	var u *db.User
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		u, err = q.UpdateUser(ctx, &db.UpdateUserParams{
			ID:                   UserIDFromContext(ctx),
			Name:                 p.Name,
			Picture:              p.Picture,
			DisablePasswordReset: p.DisablePasswordReset,
		})
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

// SharedWorkspacesError refuses an account deletion while the account owns
// workspaces other people still use.
type SharedWorkspacesError struct {
	Names []string
}

func (e *SharedWorkspacesError) Error() string {
	return "iam: account owns shared workspaces: " + strings.Join(e.Names, ", ")
}

// DeleteUser deletes the request user. Workspaces the user owns alone go
// with the account, a workspace with other members must change owner first
// (SharedWorkspacesError). Credentials, sessions, and memberships cascade.
func (s *Service) DeleteUser(ctx context.Context) error {
	u, err := s.GetUser(ctx)
	if err != nil {
		return err
	}
	err = s.conn.WithTx(ctx, func(q *db.Queries) error {
		owned, err := q.ListOwnedWorkspaces(ctx, u.ID)
		if err != nil {
			return err
		}
		var shared []string
		for _, w := range owned {
			if w.MemberCount > 1 {
				shared = append(shared, w.Name)
			}
		}
		if len(shared) > 0 {
			return &SharedWorkspacesError{Names: shared}
		}
		for _, w := range owned {
			if err := q.DeleteWorkspace(ctx, w.ID); err != nil {
				return err
			}
		}
		return q.DeleteUser(ctx, u.ID)
	})
	if err != nil {
		return err
	}
	s.record(ctx, Event{Action: ActionUserDeleted, Kind: KindUser, UserID: u.ID, Email: u.Email})
	return nil
}

// DeleteUnverifiedUsers removes accounts whose email was never verified
// before cutoff and reports how many went. It backs a hygiene job; the grace
// period is the caller's policy.
func (s *Service) DeleteUnverifiedUsers(ctx context.Context, cutoff time.Time) (int64, error) {
	return s.sys.DeleteUnverifiedUsers(ctx, cutoff)
}

// VerifyUserEmail marks the account's email as verified.
func (s *Service) VerifyUserEmail(ctx context.Context, userID string) error {
	return s.sys.VerifyUserEmail(ctx, userID)
}
