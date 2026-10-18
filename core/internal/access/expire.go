// Package access ends what was only granted for a while.
package access

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const expireTick = time.Minute

// ExpireLoop deletes grants past their end and ends requests nobody answered. Resolvers skip ended grants already,
// the delete is what makes hosts drop them and close the sessions that use them. Each is written to the audit log
// through write, one at a time, so a big batch never floods the pool.
func ExpireLoop(ctx context.Context, conn *db.Connection, write func(context.Context, *audit.Event) error) {
	ticker := time.NewTicker(expireTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := Expire(ctx, conn, write); err != nil {
			slog.Error("expire grants", "error", err)
		}
		if err := expireRequests(ctx, conn, write); err != nil {
			slog.Error("expire access requests", "error", err)
		}
	}
}

// Expire is one pass over the grants, on its own for tests. It needs no lock, a row is only returned to the one
// delete that removed it.
func Expire(ctx context.Context, conn *db.Connection, write func(context.Context, *audit.Event) error) error {
	workspaces, err := conn.Sys().ListWorkspacesWithExpiredGrants(ctx)
	if err != nil {
		return err
	}
	for _, workspaceID := range workspaces {
		// A transaction per workspace, the state version is bumped once per transaction and workspace.
		var gone []*db.DeleteExpiredGrantsRow
		if err := conn.SysTx(ctx, func(q *db.Queries) error {
			gone, err = q.DeleteExpiredGrants(ctx, workspaceID)
			return err
		}); err != nil {
			return err
		}
		for _, g := range gone {
			logEvent(ctx, write, &audit.Event{
				WorkspaceID: workspaceID,
				Action:      "GrantExpired",
				Target:      g.AccountID,
				Details: map[string]any{
					"subject_kind": g.SubjectKind,
					"subject_id":   g.SubjectID,
					"target":       g.TargetName,
					"username":     g.Username,
					"expires_at":   g.ExpiresAt,
				},
			})
		}
	}
	return nil
}

// expireRequests ends the requests nobody answered within a day.
func expireRequests(ctx context.Context, conn *db.Connection, write func(context.Context, *audit.Event) error) error {
	expired, err := conn.Sys().ExpireAccessRequests(ctx)
	if err != nil {
		return err
	}
	for _, r := range expired {
		logEvent(ctx, write, &audit.Event{WorkspaceID: r.WorkspaceID, Action: "AccessRequestExpired", Target: r.ID})
	}
	return nil
}

func logEvent(ctx context.Context, write func(context.Context, *audit.Event) error, e *audit.Event) {
	e.ActorKind, e.OK = "system", true
	if err := write(ctx, e); err != nil {
		slog.Warn("expiry not written to the audit log", "error", err, "action", e.Action, "target", e.Target)
	}
}
