package daemon

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// Past the burst one daemon's events are stored at reportRate, and a reconnect is no new burst.
func TestReportsArePacedPerDaemon(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestPool(t)
		report := &nokkuv1.ConnectionReport{Events: make([]*nokkuv1.ConnectionEvent, 100)}
		for i := range report.GetEvents() {
			report.Events[i] = &nokkuv1.ConnectionEvent{}
		}
		took := func(daemonID string) time.Duration {
			t.Helper()
			start := time.Now()
			row := &db.GetDaemonRow{Daemon: db.Daemon{ID: daemonID, WorkspaceID: "w1"}}
			require.NoError(t, p.storeReport(t.Context(), row, report))
			return time.Since(start)
		}
		paced := 100 * time.Second / reportRate

		conn := p.registerDaemon(t.Context(), "d1", "w1")
		assert.Zero(t, took("d1"), "inside the burst")
		assert.Zero(t, took("d1"), "inside the burst")
		assert.Equal(t, paced, took("d1"), "past the burst")

		p.unregisterDaemon("d1", conn)
		p.registerDaemon(t.Context(), "d1", "w1")
		assert.Equal(t, paced, took("d1"), "a reconnect was a new burst")
		assert.Zero(t, took("d2"), "one daemon's flood held another back")

		quiet := p.registerDaemon(t.Context(), "d3", "w1")
		assert.Zero(t, took("d3"))
		time.Sleep(time.Minute)
		p.unregisterDaemon("d3", quiet)
		p.reportMu.Lock()
		assert.NotContains(t, p.reportLimits, "d3", "a daemon that was not held back is remembered")
		assert.Contains(t, p.reportLimits, "d1")
		p.reportMu.Unlock()
	})
}
