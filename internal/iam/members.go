package iam

import (
	"context"
	"errors"

	"github.com/nokku-sh/nokku/internal/db"
)

// ErrSeatLimit marks a join refused by the plan's seat cap, so a caller with
// its own error shape (SCIM) can tell it apart from a store failure.
var ErrSeatLimit = errors.New("seat limit reached")

// EnsureMember adds userID to workspaceID on the caller's querier. Taking the
// querier rather than opening a transaction keeps the seat count and the
// insert in one transaction, which is what makes the row lock meaningful: two
// concurrent joins serialize on it instead of overselling the last seat.
//
// An existing member always passes, so a re-sync or a repeat login cannot fail
// because the workspace filled up after the member was added.
func (s *Service) EnsureMember(
	ctx context.Context,
	q db.Querier,
	userID, workspaceID string,
) error {
	// Without a seat gate there is nothing to count and nothing to lock: the
	// insert is an idempotent upsert.
	if s.CanJoin == nil {
		return q.EnsureWorkspaceMember(ctx, &db.EnsureWorkspaceMemberParams{
			UserID:      userID,
			WorkspaceID: workspaceID,
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
	if err := s.CanJoin(ctx, workspaceID, used); err != nil {
		// Join the sentinel so the caller can classify the denial while the
		// original error still carries the plan-specific message.
		return errors.Join(ErrSeatLimit, err)
	}

	return q.EnsureWorkspaceMember(ctx, &db.EnsureWorkspaceMemberParams{
		UserID:      userID,
		WorkspaceID: workspaceID,
	})
}

// JoinWorkspace runs EnsureMember in its own system transaction, for callers
// that have none, such as an SSO login landing in a provider's workspace.
func (s *Service) JoinWorkspace(ctx context.Context, userID, workspaceID string) error {
	return s.conn.WithTx(ctx, func(q *db.Queries) error {
		return s.EnsureMember(ctx, q, userID, workspaceID)
	})
}
