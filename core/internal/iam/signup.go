package iam

import (
	"cmp"
	"context"
	"errors"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// createUser is the one way an account comes to be. The seat cap shares its tx, so joins cannot oversell.
func (s *Service) createUser(ctx context.Context, q *db.Queries, p db.CreateUserWithIDParams) (*db.User, error) {
	p.ID = uuid.NewV7().String()
	p.Email = NormalizeEmail(p.Email)
	p.Role = cmp.Or(p.Role, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	if p.Role != nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER {
		if err := s.checkSeat(ctx, q); err != nil {
			return nil, err
		}
	}
	u, err := q.CreateUserWithID(ctx, &p)
	if err != nil {
		return nil, mapUserError(err)
	}
	return u, nil
}

// checkSeat locks the workspace row, so two callers never both take the last seat.
func (s *Service) checkSeat(ctx context.Context, q *db.Queries) error {
	if s.canJoin == nil {
		return nil
	}
	if _, err := q.GetWorkspaceForUpdate(ctx); err != nil {
		return err
	}
	ws := actor.WorkspaceIDFromContext(ctx)
	used, err := q.CountActiveUsers(ctx, ws)
	if err != nil {
		return err
	}
	if err := s.canJoin(ctx, ws, used); err != nil {
		return errors.Join(ErrSeatLimit, err)
	}
	return nil
}

// CreateOwner makes the first user of a fresh workspace. The seat cap does not apply, there is nobody to count yet.
func (s *Service) CreateOwner(ctx context.Context, email, name string) (*db.User, error) {
	var u *db.User
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		u, err = s.createUser(ctx, q, db.CreateUserWithIDParams{
			Email: email, Name: name, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	s.record(ctx, event{Action: actionUserCreated, Kind: actor.KindUser, UserID: u.ID, Email: u.Email})
	return u, nil
}
