package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
)

func seedTarget(t *testing.T, cfg *config.Config, workspaceID string) string {
	t.Helper()
	var targetID string
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		target, err := q.CreateTarget(t.Context(), &db.CreateTargetParams{
			WorkspaceID: workspaceID,
			Name:        "web-1",
			Endpoints:   []string{"10.0.0.1:22"},
		})
		if err != nil {
			return err
		}
		targetID = target.ID
		return nil
	}))
	return targetID
}

func TestSyncTargetUsers(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	targetID := seedTarget(t, cfg, workspaceID)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	hostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	editorAuth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleEditor))
	editor := nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL, editorAuth)
	principals := nokkuv1connect.NewPrincipalServiceClient(srv.Client(), srv.URL, editorAuth)
	_, err = editor.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		WorkspaceId:   &workspaceID,
		TargetId:      &targetID,
		HostPublicKey: &hostKey,
		Usernames:     []string{"root", "deploy"},
		Endpoints:     []string{"10.0.0.2:22"},
	})
	require.NoError(t, err)

	got, err := editor.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{WorkspaceId: &workspaceID, Id: &targetID})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.2:22"}, got.GetTarget().GetEndpoints(), "endpoints replaced")
	assert.Equal(t, hostKey, got.GetTarget().GetHostPublicKey(), "host key pinned")
	assert.Contains(t, got.GetTarget().GetMetadata(), "last_manual_sync", "manual sync stamped")

	usernames := func() []string {
		res, err := principals.ListPrincipals(t.Context(), &nokkuv1.ListPrincipalsRequest{
			WorkspaceId: &workspaceID,
			TargetId:    &targetID,
			Limit:       new(int32(100)),
		})
		require.NoError(t, err)
		var out []string
		for _, p := range res.GetPrincipals() {
			out = append(out, p.GetUsername())
		}
		return out
	}
	assert.ElementsMatch(t, []string{"root", "deploy"}, usernames())

	// A report without endpoints or key adds users and keeps the rest.
	_, err = editor.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		WorkspaceId: &workspaceID,
		TargetId:    &targetID,
		Usernames:   []string{"ops"},
	})
	require.NoError(t, err)
	got, err = editor.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{WorkspaceId: &workspaceID, Id: &targetID})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.2:22"}, got.GetTarget().GetEndpoints(), "endpoints kept")
	assert.Equal(t, hostKey, got.GetTarget().GetHostPublicKey(), "host key kept")
	assert.ElementsMatch(t, []string{"root", "deploy", "ops"}, usernames(), "earlier users are never deleted")

	viewer := nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL,
		header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleViewer)))
	_, err = viewer.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		WorkspaceId: &workspaceID,
		TargetId:    &targetID,
		Usernames:   []string{"intruder"},
	})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "viewer may not sync, got %v", err)
}
