//go:build integration

package api_test

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// The dashboard counts in SQL and reads two short lists, however many daemons the workspace has.
func TestDashboardDaemons(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	_, accepted := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	_, pending := enrollTestDaemon(t, cfg, srv, workspaceID, false)

	var all []*db.ListDaemonsRow
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) (err error) {
		all, err = q.ListDaemons(t.Context(), &db.ListDaemonsParams{SeenAfter: time.Now().Add(-db.DaemonOnlineWindow)})
		return err
	})

	viewer := nokkuv1connect.NewDashboardServiceClient(srv.Client(), srv.URL,
		header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)))
	res, err := viewer.GetDashboard(t.Context(), &nokkuv1.GetDashboardRequest{})
	require.NoError(t, err)

	assert.EqualValues(t, len(all), res.GetDaemons(), "every daemon counts")
	require.NotEmpty(t, res.GetPendingDaemons())
	assert.Equal(t, pending.GetId(), res.GetPendingDaemons()[0].GetId(), "the newest pending daemon comes first")
	assert.LessOrEqual(t, len(res.GetPendingDaemons()), 5)
	assert.LessOrEqual(t, len(res.GetOfflineDaemons()), 5)
	for _, d := range res.GetOfflineDaemons() {
		assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, d.GetStatus(), "only accepted daemons are missed")
		assert.NotEqual(t, pending.GetId(), d.GetId())
	}
	assert.False(t, slices.ContainsFunc(res.GetPendingDaemons(), func(d *nokkuv1.Daemon) bool {
		return d.GetId() == accepted.GetId()
	}), "an accepted daemon waits for nobody")
}

// Sign-ins and sessions happen all day, they must not push the real changes out of the short list.
func TestDashboardRecentChangesSkipRoutine(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	editorAuth := header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))

	name := uniq("changes")
	_, err := nokkuv1connect.NewTeamServiceClient(srv.Client(), srv.URL, editorAuth).
		CreateTeam(t.Context(), &nokkuv1.CreateTeamRequest{Name: &name})
	require.NoError(t, err)

	dashboard := nokkuv1connect.NewDashboardServiceClient(srv.Client(), srv.URL, editorAuth)
	// The audit write is detached from the request, so the row shows up a moment later.
	var changes []*nokkuv1.EventLog
	require.Eventually(t, func() bool {
		res, err := dashboard.GetDashboard(t.Context(), &nokkuv1.GetDashboardRequest{})
		if err != nil {
			return false
		}
		changes = res.GetRecentChanges()
		return slices.ContainsFunc(changes, func(e *nokkuv1.EventLog) bool { return e.GetTarget() == name })
	}, 5*time.Second, 50*time.Millisecond, "the new team is no recent change")

	assert.LessOrEqual(t, len(changes), 8)
	for _, e := range changes {
		assert.NotContains(t, []string{"Login", "SessionIssued", "RelayOpen", "RelayClose", "GetRecording"},
			e.GetAction(), "a routine action took a slot")
	}
}
