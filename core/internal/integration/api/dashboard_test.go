//go:build integration

package api_test

import (
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// The count covers every daemon, the two lists stay short.
func TestDashboardDaemons(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	_, accepted := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	_, pending := enrollTestDaemon(t, cfg, srv, workspaceID, false)

	var all []*db.ListDaemonsRow
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) (err error) {
		all, err = q.ListDaemons(t.Context(), &db.ListDaemonsParams{})
		return err
	})

	viewer := nokkuv1connect.NewDashboardServiceClient(
		clientOn(
			srv,
			header(
				"Authorization",
				"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER),
			),
		),
	)
	res, err := viewer.GetDashboard(t.Context(), &nokkuv1.GetDashboardRequest{})
	require.NoError(t, err)

	assert.EqualValues(t, len(all), res.GetDaemons(), "every daemon counts")
	require.NotEmpty(t, res.GetPendingDaemons())
	assert.Equal(t, pending.GetId(), res.GetPendingDaemons()[0].GetId(), "the newest pending daemon comes first")
	assert.LessOrEqual(t, len(res.GetPendingDaemons()), 5)
	assert.LessOrEqual(t, len(res.GetOfflineServers()), 5)
	for _, server := range res.GetOfflineServers() {
		d := server.GetDaemon()
		require.NotNil(t, d, "an offline server comes with its daemon")
		assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, d.GetStatus(), "only accepted daemons are missed")
		assert.NotEqual(t, pending.GetId(), d.GetId())
	}
	assert.False(t, slices.ContainsFunc(res.GetPendingDaemons(), func(d *nokkuv1.Daemon) bool {
		return d.GetId() == accepted.GetId()
	}), "an accepted daemon waits for nobody")
}

// Sign-ins happen all day, they must not push real changes off the short list.
func TestDashboardRecentChangesSkipRoutine(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	editorAuth := header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))

	name := uniq("changes")
	_, err := nokkuv1connect.NewTeamServiceClient(clientOn(srv, editorAuth)).
		CreateTeam(t.Context(), &nokkuv1.CreateTeamRequest{Name: &name})
	require.NoError(t, err)

	dashboard := nokkuv1connect.NewDashboardServiceClient(
		clientOn(srv, editorAuth),
	)
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

// Grants given in one go end as one row, the ones that last past a day stay off the list.
func TestDashboardEndingGrants(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	// Earlier tests' servers go, a daemon with its target as the API does. Only the owner gets past RLS.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	for _, table := range []string{"daemons", "targets"} {
		_, err = owner.Exec(t.Context(), "DELETE FROM "+table+" WHERE workspace_id = $1", workspaceID)
		require.NoError(t, err)
	}
	require.NoError(t, owner.Close(t.Context()))

	soon := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	later := time.Now().Add(48 * time.Hour)

	var mia string
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		s := graphSeed{t: t, q: q, targets: map[string]string{}}
		mia = s.member("Mia")
		grant := func(accountID string, expiresAt *time.Time) {
			require.NoError(t, q.PutGrant(t.Context(), &db.PutGrantParams{
				AccountID: accountID, SubjectKind: db.SubjectKindUser, SubjectID: mia, ExpiresAt: expiresAt,
			}))
		}
		grant(s.account("web-2", nil, "deploy"), &soon)
		grant(s.account("web-1", nil, "deploy"), &soon)
		grant(s.account("db-1", nil, "deploy"), &later)
		grant(s.account("db-2", nil, "root"), nil)
		return nil
	})

	viewer := nokkuv1connect.NewDashboardServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER))))
	res, err := viewer.GetDashboard(t.Context(), &nokkuv1.GetDashboardRequest{})
	require.NoError(t, err)

	require.Len(t, res.GetEndingGrants(), 1, "only the grants that end within a day, as one row")
	assert.EqualValues(t, 1, res.GetEndingGrantsTotal())
	g := res.GetEndingGrants()[0]
	assert.Equal(t, mia, g.GetSubjectId())
	assert.Equal(t, "Mia", g.GetSubjectName())
	assert.Equal(t, nokkuv1.SubjectKind_SUBJECT_KIND_USER, g.GetSubjectKind())
	assert.Equal(t, "deploy", g.GetUsername())
	assert.WithinDuration(t, soon, g.GetExpiresAt().AsTime(), time.Second)
	assert.EqualValues(t, 2, g.GetTargetCount())
	var names []string
	for _, target := range g.GetTargets() {
		names = append(names, target.GetName())
	}
	assert.Equal(t, []string{"web-1", "web-2"}, names, "the servers come sorted by name")
}
