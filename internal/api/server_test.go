package api

import (
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/db"
)

// A public RPC must not buffer a body of any size before it is even validated.
func TestRequestSizeLimit(t *testing.T) {
	_, srv := newTestAPI(t)
	_, err := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL).
		Login(t.Context(), &nokkuv1.LoginRequest{
			Email:    new("user@api.test"),
			Password: new(strings.Repeat("x", maxMessageBytes+1)),
		})
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "got %v", err)
}

// The audit webhook secret signs events to the customer's SIEM. Only the
// people who manage it may read it back.
func TestWorkspaceHidesWebhookFromMembers(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		_, err := q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{
			WorkspaceID: workspaceID,
			Settings: &nokkuv1.WorkspaceSettings{
				AuditWebhookUrl:    new("https://siem.example/hook"),
				AuditWebhookSecret: new("s3cret"),
			},
		})
		return err
	}))

	client := func(role db.Role) nokkuv1connect.WorkspaceServiceClient {
		return nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL,
			header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, role)))
	}

	for _, role := range []db.Role{db.RoleMember, db.RoleEditor} {
		got, err := client(role).GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{WorkspaceId: &workspaceID})
		require.NoError(t, err)
		assert.Empty(t, got.GetWorkspace().GetSettings().GetAuditWebhookSecret(), "%s reads the secret", role)
		assert.Empty(t, got.GetWorkspace().GetSettings().GetAuditWebhookUrl(), "%s reads the url", role)

		list, err := client(role).ListWorkspaces(t.Context(), &nokkuv1.ListWorkspacesRequest{})
		require.NoError(t, err)
		require.Len(t, list.GetWorkspaces(), 1)
		assert.Empty(t, list.GetWorkspaces()[0].GetSettings().GetAuditWebhookSecret(), "%s lists the secret", role)
	}

	got, err := client(db.RoleAdmin).GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{WorkspaceId: &workspaceID})
	require.NoError(t, err)
	assert.Equal(t, "s3cret", got.GetWorkspace().GetSettings().GetAuditWebhookSecret())
}
