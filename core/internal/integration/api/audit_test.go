//go:build integration

package api_test

import (
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// A denied call is audited. A session of another workspace does not exist on this host, so it leaves nothing.
func TestAuditDeniedCall(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	viewer := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	other := seedOtherWorkspace(t, cfg)
	outsider := seedUser(t, cfg, other, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	_, stranger, err := cfg.IAM.IssueToken(
		actor.WithWorkspace(t.Context(), actor.Workspace{ID: other, BaseURL: cfg.FullURL()}),
		iam.TokenParams{SubjectID: outsider.ID, Kind: actor.KindUser, Method: iam.MethodPasskey},
	)
	require.NoError(t, err)

	deleteTarget := func(token, id string) connect.Code {
		targets := nokkuv1connect.NewTargetServiceClient(
			connect.NewClient(
				connecthttp.NewTransport(srv.Client(), srv.URL),
				header("Authorization", "Bearer "+token),
			),
		)
		_, err := targets.DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: &id})
		return connect.CodeOf(err)
	}
	// The write is detached from the request, so the row shows up a moment later.
	rows := func(target string) []*db.ListAuditLogsRow {
		var out []*db.ListAuditLogsRow
		_ = cfg.Conn.TenantTx(wsCtx(t, cfg), func(q *db.Queries) (err error) {
			out, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
				Target: &target, Limit: 2,
			})
			return err
		})
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

// The log keeps the name of a service account, the account may be long gone when somebody reads the row.
func TestAuditNamesServiceAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	name := uniq("ci")
	accounts := nokkuv1connect.NewServiceAccountServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), adminAuth),
	)
	sa, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{Name: &name})
	require.NoError(t, err)
	token := serviceAccountToken(t, accounts, sa.GetServiceAccount().GetId(), nil)

	target := uuid.NewV7().String()
	_, err = nokkuv1connect.NewTargetServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), header("Authorization", "Bearer "+token))).
		DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: &target})
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	var rows []*db.ListAuditLogsRow
	require.Eventually(t, func() bool {
		_ = cfg.Conn.TenantTx(wsCtx(t, cfg), func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{Target: &target, Limit: 2})
			return err
		})
		return len(rows) == 1
	}, 5*time.Second, 20*time.Millisecond, "no audit row for the service account's call")
	assert.Equal(t, string(actor.KindServiceAccount), rows[0].ActorKind)
	assert.Equal(t, name, rows[0].ActorName, "the row must carry the name, not only the id")
}
