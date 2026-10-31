package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const retireTick = time.Minute

// RetireLoop deletes the daemons of ephemeral tokens that have been away longer than their retire_after. A daemon
// in connected is never away. Each one is written to the audit log through record. The session stays, like after an
// admin's delete, so a host that does come back is told it is rejected and drops its cached principals.
func RetireLoop(
	ctx context.Context,
	conn connection,
	connected func() []string,
	record func(context.Context, *audit.Event),
) {
	started := time.Now()
	ticker := time.NewTicker(retireTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := Retire(ctx, conn, connected(), started, record); err != nil {
			slog.Error("retire ephemeral daemons", "error", err)
		}
	}
}

// Retire is one pass of RetireLoop, on its own for tests. Nothing counts as away before started.
func Retire(
	ctx context.Context,
	conn connection,
	connected []string,
	started time.Time,
	record func(context.Context, *audit.Event),
) error {
	var retired []*db.DeleteRetiredDaemonsRow
	err := conn.SysTx(ctx, func(q *db.Queries) error {
		locked, err := q.TryAdvisoryXactLock(ctx, "daemon-retire")
		if err != nil || !locked {
			return err
		}
		retired, err = q.DeleteRetiredDaemons(ctx, &db.DeleteRetiredDaemonsParams{
			StartedAt: started,
			Connected: connected,
		})
		return err
	})
	if err != nil {
		return err
	}
	for _, d := range retired {
		record(actor.WithWorkspace(ctx, actor.Workspace{ID: d.WorkspaceID}), &audit.Event{
			Action:  "RetireDaemon",
			Target:  d.ID,
			OK:      true,
			Details: map[string]any{"name": d.Name},
		})
	}
	return nil
}
