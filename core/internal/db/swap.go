package db

import "context"

// TransferOwnership is false for an unknown or inactive new owner. Call it in a
// transaction, only a rollback gives the old owner the role back.
func (q *Queries) TransferOwnership(ctx context.Context, newOwnerID string) (bool, error) {
	demoted, err := q.DemoteOwner(ctx)
	if err != nil {
		return false, err
	}
	// Someone else moved the ownership first.
	if demoted == 0 {
		return false, ErrPermissionDenied
	}
	promoted, err := q.PromoteOwner(ctx, newOwnerID)
	return promoted == 1, err
}
