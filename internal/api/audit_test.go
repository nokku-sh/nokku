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

	"github.com/nokku-sh/nokku/internal/db"
)

// A denied call is audited, but only a member's lands in the workspace log.
func TestAuditDeniedCall(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	viewer := seedMember(t, cfg, workspaceID, db.RoleViewer)
	stranger := seedMember(t, cfg, seedWorkspace(t, cfg), db.RoleAdmin)

	deleteTarget := func(token, id string) {
		targets := nokkuv1connect.NewTargetServiceClient(
			srv.Client(), srv.URL, header("Authorization", "Bearer "+token),
		)
		_, err := targets.DeleteTarget(
			t.Context(),
			&nokkuv1.DeleteTargetRequest{WorkspaceId: &workspaceID, Id: &id},
		)
		require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	}
	// The write is detached from the request, so the row shows up a moment later.
	logged := func(target string) *db.ListAuditLogsRow {
		var rows []*db.ListAuditLogsRow
		require.Eventually(t, func() bool {
			err := cfg.Conn.WithTx(t.Context(), func(q *db.Queries) (err error) {
				rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{Target: &target, Limit: 2})
				return err
			})
			return err == nil && len(rows) > 0
		}, 5*time.Second, 20*time.Millisecond, "no audit row for the denied call")
		require.Len(t, rows, 1)
		return rows[0]
	}

	target := uuid.NewV7().String()
	deleteTarget(viewer, target)
	assert.Equal(t, &workspaceID, logged(target).WorkspaceID,
		"a member's denied call belongs in the workspace log")

	long := uuid.NewV7().String() + strings.Repeat("x", 10_000)
	deleteTarget(stranger, long)
	row := logged(long[:256])
	assert.Nil(t, row.WorkspaceID, "a stranger's call must stay out of the workspace log")
	assert.Contains(t, string(row.Details), workspaceID, "their own log keeps the workspace they asked for")
}
