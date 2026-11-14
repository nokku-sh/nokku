//go:build integration

package api_test

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// A denied call is audited. Another workspace's session leaves nothing here.
func TestAuditDeniedCall(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	viewer := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	other := seedOtherWorkspace(t, cfg)
	outsider := seedUser(t, cfg, other, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	_, stranger, err := cfg.IAM.IssueSignIn(
		actor.WithWorkspace(t.Context(), actor.Workspace{ID: other, BaseURL: cfg.FullURL()}),
		outsider,
		iam.TokenParams{Kind: actor.KindUser, Method: iam.MethodPasskey},
	)
	require.NoError(t, err)

	deleteTarget := func(token, id string) connect.Code {
		targets := nokkuv1connect.NewTargetServiceClient(
			clientOn(srv, header("Authorization", "Bearer "+token)),
		)
		_, err := targets.DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: &id})
		return connect.CodeOf(err)
	}
	rows := func(target string) []*db.ListAuditLogsRow {
		var out []*db.ListAuditLogsRow
		assert.NoError(t, cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
			out, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
				Target: &target, Limit: 2,
			})
			return err
		}))
		return out
	}

	target := uuid.NewV7().String()
	assert.Equal(t, connect.CodePermissionDenied, deleteTarget(viewer, target))
	require.Eventually(t, func() bool { return len(rows(target)) == 1 },
		5*time.Second, 20*time.Millisecond, "no audit row for the denied call")
	assert.Equal(t, workspaceID, rows(target)[0].WorkspaceID, "a denied call belongs in the workspace log")

	long := uuid.NewV7().String() + strings.Repeat("x", 10_000)
	assert.Equal(t, connect.CodeUnauthenticated, deleteTarget(stranger, long),
		"a session of another workspace authenticated here")
	time.Sleep(200 * time.Millisecond)
	assert.Empty(t, rows(long[:256]), "a stranger's call reached the log")
}

// Forensics need the exact address, not the /64 that rate limits count by.
func TestAuditKeepsTheExactAddress(t *testing.T) {
	cfg, srv := newTestAPI(t)
	viewer := seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	// The test server is on loopback, which may name the client by default.
	targets := nokkuv1connect.NewTargetServiceClient(
		clientOn(
			srv,
			header("Authorization", "Bearer "+viewer),
			header("X-Forwarded-For", "2001:db8:abcd:1234::7"),
		),
	)
	target := uuid.NewV7().String()
	_, err := targets.DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: &target})
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	var rows []*db.ListAuditLogsRow
	require.Eventually(t, func() bool {
		_ = cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{Target: &target, Limit: 1})
			return err
		})
		return len(rows) == 1
	}, 5*time.Second, 20*time.Millisecond, "no audit row for the denied call")
	assert.Equal(t, "2001:db8:abcd:1234::7", rows[0].Ip)
}

// The log keeps the name, the account may be long gone when someone reads it.
func TestAuditNamesServiceAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	name := uniq("ci")
	accounts := nokkuv1connect.NewServiceAccountServiceClient(
		clientOn(srv, adminAuth),
	)
	sa, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{Name: &name})
	require.NoError(t, err)
	token := serviceAccountToken(t, accounts, sa.GetServiceAccount().GetId(), nil)

	target := uuid.NewV7().String()
	_, err = nokkuv1connect.NewTargetServiceClient(clientOn(srv, header("Authorization", "Bearer "+token))).
		DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: &target})
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	var rows []*db.ListAuditLogsRow
	require.Eventually(t, func() bool {
		_ = cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{Target: &target, Limit: 2})
			return err
		})
		return len(rows) == 1
	}, 5*time.Second, 20*time.Millisecond, "no audit row for the service account's call")
	assert.Equal(t, string(actor.KindServiceAccount), rows[0].ActorKind)
	assert.Equal(t, name, rows[0].ActorName, "the row must carry the name, not only the id")
}

// A daemon has no name of its own, its rows carry its server's.
func TestAuditNamesDaemon(t *testing.T) {
	cfg, srv := newTestAPI(t)
	key, enrolled := enrollTestDaemon(t, cfg, srv, testWorkspace.ID, true)
	target, err := cfg.Conn.Tenant().GetTargetByDaemon(wsCtx(t), new(enrolled.GetId()))
	require.NoError(t, err)

	// Refused for the key, the interceptor still writes the row.
	_, _ = nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, daemonAuth(
		t, cfg, key, enrolled.GetAccessToken(),
		nokkuv1connect.DaemonControlServiceSignHostCertificateProcedure,
	))).SignHostCertificate(t.Context(), &nokkuv1.SignHostCertificateRequest{PublicKey: new("ssh-ed25519 AAAA")})

	for _, action := range []string{"SessionIssued", "SignHostCertificate"} {
		var rows []*db.ListAuditLogsRow
		require.Eventually(t, func() bool {
			rows, _ = cfg.Conn.Tenant().ListAuditLogs(wsCtx(t), &db.ListAuditLogsParams{
				ActorIds: []string{enrolled.GetId()}, Actions: []string{action}, Limit: 1,
			})
			return len(rows) == 1
		}, 5*time.Second, 20*time.Millisecond, "no %s row for the daemon", action)
		assert.Equal(t, target.Name, rows[0].ActorName, "%s must name the daemon by its server", action)
	}
}

// A deleted team keeps its name in the log, and a search for a server finds the grants on it.
func TestAuditStoresNames(t *testing.T) {
	cfg, srv := newTestAPI(t)
	editor := clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)))
	server := uniq("names")
	teamName := uniq("crew")

	var accountID, personID string
	inWorkspace(t, cfg, testWorkspace.ID, func(q *db.Queries) error {
		seed := graphSeed{t: t, q: q, targets: map[string]string{}}
		accountID = seed.account(server, nil, "deploy")
		personID = seed.member("Ada Names")
		return nil
	})

	teams := nokkuv1connect.NewTeamServiceClient(editor)
	team, err := teams.CreateTeam(t.Context(), &nokkuv1.CreateTeamRequest{Name: &teamName})
	require.NoError(t, err)
	teamID := team.GetTeam().GetId()
	_, err = teams.AddTeamMember(t.Context(), &nokkuv1.AddTeamMemberRequest{TeamId: &teamID, UserId: &personID})
	require.NoError(t, err)
	_, err = nokkuv1connect.NewTargetAccountServiceClient(editor).AddSubjects(t.Context(), &nokkuv1.AddSubjectsRequest{
		Id:         &accountID,
		SubjectIds: []string{teamID},
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_TEAM.Enum(),
	})
	require.NoError(t, err)
	_, err = teams.DeleteTeam(t.Context(), &nokkuv1.DeleteTeamRequest{Id: &teamID})
	require.NoError(t, err)

	details := func(action string, params *db.ListAuditLogsParams) map[string]any {
		params.Actions, params.Limit = []string{action}, 1
		var rows []*db.ListAuditLogsRow
		require.Eventually(t, func() bool {
			_ = cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
				rows, err = q.ListAuditLogs(t.Context(), params)
				return err
			})
			return len(rows) == 1 && rows[0].Ok
		}, 5*time.Second, 20*time.Millisecond, "no %s event", action)
		var out map[string]any
		require.NoError(t, json.Unmarshal(rows[0].Details, &out))
		return out
	}

	grant := details("AddSubjects", &db.ListAuditLogsParams{Search: &server})
	assert.Equal(t, server, grant["target"], "a search for the server finds its grant")
	assert.Equal(t, "deploy", grant["username"])
	assert.Equal(t, "team", grant["subject_kind"])
	assert.Equal(t, []any{teamName}, grant["subjects"])

	member := details("AddTeamMember", &db.ListAuditLogsParams{Target: &teamID})
	assert.Equal(t, teamName, member["name"])
	assert.Equal(t, "Ada Names", member["member"])

	assert.Equal(t, teamName, details("DeleteTeam", &db.ListAuditLogsParams{Target: &teamID})["name"],
		"the delete lost the name of what it removed")
}

// Your own activity filters on the server and stays yours, whatever actor the filter names.
func TestMyActivityFilters(t *testing.T) {
	cfg, srv := newTestAPI(t)
	editor := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	conn := clientOn(srv, header("Authorization", "Bearer "+sessionFor(t, cfg, editor)))
	name := uniq("mine")
	_, err := nokkuv1connect.NewTeamServiceClient(conn).CreateTeam(t.Context(), &nokkuv1.CreateTeamRequest{Name: &name})
	require.NoError(t, err)

	util := nokkuv1connect.NewUtilServiceClient(conn)
	actions := func(f *nokkuv1.AuditLogFilter) []string {
		res, err := util.ListMyActivity(t.Context(), &nokkuv1.ListMyActivityRequest{
			Limit: new(int32(100)), Filter: f,
		})
		require.NoError(t, err)
		var out []string
		for _, l := range res.GetLogs() {
			assert.Equal(t, editor.ID, l.GetActorId(), "someone else's event")
			out = append(out, l.GetAction())
		}
		return out
	}

	require.Eventually(t, func() bool {
		return slices.Contains(actions(&nokkuv1.AuditLogFilter{Actions: []string{"CreateTeam"}}), "CreateTeam")
	}, 5*time.Second, 20*time.Millisecond, "the new team is not in your activity")
	assert.NotContains(t, actions(&nokkuv1.AuditLogFilter{ExcludedActions: []string{"CreateTeam"}}), "CreateTeam")
	assert.Contains(t, actions(&nokkuv1.AuditLogFilter{ActorIds: []string{uuid.NewV7().String()}}), "CreateTeam",
		"the filter's actor replaced yours")
}

// Approving a daemon reads as its own action, not as a settings change.
func TestAuditNamesTheApproval(t *testing.T) {
	cfg, srv := newTestAPI(t)
	_, enrolled := enrollTestDaemon(t, cfg, srv, testWorkspace.ID, false)
	daemons := nokkuv1connect.NewDaemonServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))))
	_, err := daemons.UpdateDaemon(t.Context(), masked(&nokkuv1.UpdateDaemonRequest{
		Id:     new(enrolled.GetId()),
		Status: nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
	}))
	require.NoError(t, err)

	var rows []*db.ListAuditLogsRow
	require.Eventually(t, func() bool {
		_ = cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
				Target: new(enrolled.GetId()), Actions: []string{"ApproveDaemon"}, Limit: 1,
			})
			return err
		})
		return len(rows) == 1
	}, 5*time.Second, 20*time.Millisecond, "no ApproveDaemon event")
	var details map[string]any
	require.NoError(t, json.Unmarshal(rows[0].Details, &details))
	assert.NotEmpty(t, details["name"])
}

// A SIEM that fetches reads forward, oldest first, and the cursor it got takes it on from there.
func TestPollAuditLogsReadsForwardFromTheCursor(t *testing.T) {
	cfg, srv := enterprise(t)
	viewer := seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	util := nokkuv1connect.NewUtilServiceClient(clientOn(srv, header("Authorization", "Bearer "+viewer)))

	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = owner.Close(context.WithoutCancel(t.Context())) })
	base := time.Now().Add(-3 * time.Hour).Truncate(time.Microsecond)
	_, err = owner.Exec(t.Context(), `
		INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp) VALUES
			($1, 'PollFirst', TRUE, $2), ($1, 'PollSecond', TRUE, $3), ($1, 'PollFresh', TRUE, NOW());
	`, pgx.QueryExecModeSimpleProtocol, testWorkspace.ID, base, base.Add(time.Second))
	require.NoError(t, err, "seed")

	poll := func(cursor string, limit int32) *nokkuv1.PollAuditLogsResponse {
		res, err := util.PollAuditLogs(t.Context(), &nokkuv1.PollAuditLogsRequest{Cursor: &cursor, Limit: &limit})
		require.NoError(t, err, "poll from %q", cursor)
		return res
	}
	before := strconv.FormatInt(base.UnixMicro()-1, 10) + "." + uuid.Nil().String()

	first := poll(before, 1)
	require.Len(t, first.GetLogs(), 1)
	assert.Equal(t, "PollFirst", first.GetLogs()[0].GetAction())
	second := poll(first.GetCursor(), 1)
	require.Len(t, second.GetLogs(), 1, "the cursor skipped or repeated an event")
	assert.Equal(t, "PollSecond", second.GetLogs()[0].GetAction())

	rest := poll(second.GetCursor(), 1000)
	for _, l := range rest.GetLogs() {
		assert.NotEqual(t, "PollFresh", l.GetAction(), "an event younger than the settle window went out")
	}
	if len(rest.GetLogs()) == 0 {
		assert.Equal(t, second.GetCursor(), rest.GetCursor(), "an empty answer keeps the cursor")
	}

	_, err = util.PollAuditLogs(
		t.Context(),
		&nokkuv1.PollAuditLogsRequest{Cursor: new("yesterday"), Limit: new(int32(1))},
	)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "a made up cursor")
}
