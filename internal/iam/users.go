package iam

import (
	"context"
	"strings"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
	emailverify "github.com/nokku-sh/nokku/internal/email"
)

// Register leaves the account unverified until the emailed link is confirmed.
func (s *Service) Register(ctx context.Context, email, name, pw string) (*db.User, error) {
	email = normalizeEmail(email)
	if err := emailverify.Verify(email, s.strict); err != nil {
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
			Kind:   actor.KindUser,
			Method: MethodPassword,
			UserID: u.ID,
			Email:  u.Email,
		},
	)
	return u, nil
}

func (s *Service) GetUser(ctx context.Context) (*db.User, error) {
	var u *db.User
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		u, err = q.GetUser(ctx, actor.UserIDFromContext(ctx))
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

func (s *Service) getUserByID(ctx context.Context, userID string) (*db.User, error) {
	u, err := s.sys.GetUser(ctx, userID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

func (s *Service) GetUserByEmail(ctx context.Context, email string) (*db.User, error) {
	u, err := s.sys.GetUserByEmail(ctx, normalizeEmail(email))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

func (s *Service) updateUser(ctx context.Context, p db.UpdateUserParams) (*db.User, error) {
	u, err := s.sys.UpdateUser(ctx, &p)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

// UpdateSelf never touches Active, nobody reactivates themselves.
func (s *Service) UpdateSelf(ctx context.Context, p db.UpdateUserParams) (*db.User, error) {
	var u *db.User
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		u, err = q.UpdateUser(ctx, &db.UpdateUserParams{
			ID:                   actor.UserIDFromContext(ctx),
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

type SharedWorkspacesError struct {
	Names []string
}

func (e *SharedWorkspacesError) Error() string {
	return "iam: account owns shared workspaces: " + strings.Join(e.Names, ", ")
}

// DeleteUser takes solo workspaces with it. Shared ones must change owner first.
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
	s.record(ctx, Event{Action: ActionUserDeleted, Kind: actor.KindUser, UserID: u.ID, Email: u.Email})
	return nil
}

func (s *Service) VerifyUserEmail(ctx context.Context, userID string) error {
	return s.sys.VerifyUserEmail(ctx, userID)
}
