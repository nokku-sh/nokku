package db

import "context"

// TransferOwnership is false when the new owner does not exist or is not active. Call it in a transaction,
// the old owner has lost the role by then and only the rollback gives it back.
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

// SetDefaultCA moves the default to one CA. Call it in a transaction, or a failure leaves no default.
func (q *Queries) SetDefaultCA(ctx context.Context, caID string) error {
	if err := q.ClearDefaultCA(ctx, caID); err != nil {
		return err
	}
	return q.MarkDefaultCA(ctx, caID)
}
