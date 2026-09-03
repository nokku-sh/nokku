package entitlement

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

// ErrNoSubscription means the workspace has no subscription row: the
// normal state of every Community workspace, not a failure.
var ErrNoSubscription = pgx.ErrNoRows

// Store adapts db.Connection to the entitlement DB interface. Lookups run
// as system transactions: plan resolution happens for workspaces that are
// not yet pinned for RLS data access (the guard interceptor runs before a
// workspace transaction is opened).
type Store struct {
	conn *db.Connection
}

func NewStore(conn *db.Connection) *Store {
	return &Store{conn: conn}
}

func (s *Store) Subscription(
	ctx context.Context,
	workspaceID string,
) (plan string, status Status, err error) {
	var sub *db.WorkspaceSubscription
	if err := s.conn.WithTx(ctx, func(q *db.Queries) (err error) {
		sub, err = q.GetSubscription(ctx, workspaceID)
		return err
	}); err != nil {
		// pgx.ErrNoRows passes through unchanged so callers can treat it as
		// the expected Community case rather than a lookup failure.
		return "", StatusInactive, err
	}
	return sub.Plan, Status(sub.Status), nil
}

func (s *Store) MemberCount(ctx context.Context, workspaceID string) (int64, error) {
	var stats *db.GetWorkspaceStatsRow
	if err := s.conn.WithTx(ctx, func(q *db.Queries) (err error) {
		stats, err = q.GetWorkspaceStats(ctx, workspaceID)
		return err
	}); err != nil {
		return 0, err
	}
	return stats.MemberCount, nil
}
