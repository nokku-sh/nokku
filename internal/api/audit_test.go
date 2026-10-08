package api

import (
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

// A denied call is audited in the workspace log. A session of another
// workspace does not exist on this host, so it leaves nothing.
func TestAuditDeniedCall(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	viewer := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	other := seedOtherWorkspace(t, cfg)
	outsider := seedUser(t, cfg, other, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	_, stranger, err := cfg.IAM.IssueSession(
		actor.WithWorkspace(t.Context(), actor.Workspace{ID: other, BaseURL: cfg.FullURL()}),
		iam.SessionParams{SubjectID: outsider.ID, Kind: actor.KindUser, Method: iam.MethodPasskey},
	)
	require.NoError(t, err)

	deleteTarget := func(token, id string) connect.Code {
		targets := nokkuv1connect.NewTargetServiceClient(
			srv.Client(), srv.URL, header("Authorization", "Bearer "+token),
		)
		_, err := targets.DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: &id})
		return connect.CodeOf(err)
	}
	// The write is detached from the request, so the row shows up a moment later.
	rows := func(target string) []*db.ListAuditLogsRow {
		var out []*db.ListAuditLogsRow
		_ = cfg.Conn.WithWorkspace(wsCtx(t, cfg), func(q *db.Queries) (err error) {
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
