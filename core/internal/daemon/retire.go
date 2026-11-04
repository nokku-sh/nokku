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

// RetireLoop deletes ephemeral daemons away past retire_after. The session
// stays, so a host that comes back is rejected and drops its cached principals.
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

// Retire is one pass of RetireLoop. Nothing counts as away before started.
func Retire(
	ctx context.Context,
	conn connection,
	connected []string,
	started time.Time,
	record func(context.Context, *audit.Event),
) error {
	var retired []*db.DeleteRetiredDaemonsRow
	err := conn.SysTx(ctx, func(q *db.Queries) (err error) {
		if err := q.QuietStateChange(ctx); err != nil {
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
