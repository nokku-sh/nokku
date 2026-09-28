package iam

import (
	"cmp"
	"context"
	"errors"

	"github.com/nokku-sh/nokku/internal/db"
)

var ErrSeatLimit = errors.New("seat limit reached")

// EnsureMember defaults role to member. It takes the caller's querier so the
// seat count and insert share one tx, and concurrent joins serialize on the
// row lock instead of overselling the last seat. Existing members always pass.
func (s *Service) EnsureMember(
	ctx context.Context,
	q db.Querier,
	userID, workspaceID, role string,
) error {
	if s.canJoin == nil {
		return q.EnsureWorkspaceMember(ctx, &db.EnsureWorkspaceMemberParams{
			UserID:      userID,
			WorkspaceID: workspaceID,
			RoleName:    cmp.Or(role, string(db.RoleMember)),
		})
	}

	if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
		WorkspaceID: workspaceID,
		UserID:      userID,
	}); err == nil {
		return nil
	}

	if _, err := q.GetWorkspaceForUpdate(ctx, workspaceID); err != nil {
		return err
	}
	used, err := q.CountWorkspaceSeats(ctx, workspaceID)
	if err != nil {
		return err
	}
	if err := s.canJoin(ctx, workspaceID, used); err != nil {
		return errors.Join(ErrSeatLimit, err)
	}

	return q.EnsureWorkspaceMember(ctx, &db.EnsureWorkspaceMemberParams{
		UserID:      userID,
		WorkspaceID: workspaceID,
		RoleName:    cmp.Or(role, string(db.RoleMember)),
	})
}

func (s *Service) JoinWorkspace(ctx context.Context, userID, workspaceID string) error {
	return s.conn.WithTx(ctx, func(q *db.Queries) error {
		return s.EnsureMember(ctx, q, userID, workspaceID, "")
	})
}
