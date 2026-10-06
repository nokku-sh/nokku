package api

import (
	"testing"
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

func TestUpdateWorkspaceOwner(t *testing.T) {
	cfg, srv := newTestAPI(t)
	var owner, member, stranger *db.User
	var workspaceID string
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) (err error) {
		for _, u := range []**db.User{&owner, &member, &stranger} {
			if *u, err = q.CreateUser(
				t.Context(),
				&db.CreateUserParams{Email: uuid.New().String() + "@api.test", Name: "u"},
			); err != nil {
				return err
			}
		}
		ws, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{Name: "owner", CreatedBy: owner.ID})
		if err != nil {
			return err
		}
		workspaceID = ws.ID
		return q.EnsureWorkspaceMember(t.Context(), &db.EnsureWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      member.ID,
			RoleName:    string(db.RoleEditor),
		})
	}))
	_, token, err := cfg.IAM.IssueSession(t.Context(), iam.SessionParams{
		SubjectID: owner.ID,
		Kind:      actor.KindUser,
		Method:    iam.MethodPassword,
	})
	require.NoError(t, err)
	workspaces := nokkuv1connect.NewWorkspaceServiceClient(
		srv.Client(), srv.URL, header("Authorization", "Bearer "+token),
	)
	transfer := func(to string) error {
		_, err := workspaces.UpdateWorkspaceOwner(
			t.Context(),
			&nokkuv1.UpdateWorkspaceOwnerRequest{WorkspaceId: &workspaceID, NewOwner: &to},
		)
		return err
	}
	// state returns who owns the workspace and the role each user holds in it.
	state := func() (ownerID string, roles map[string]string) {
		roles = map[string]string{}
		require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) (err error) {
			if ownerID, err = q.GetWorkspaceOwner(t.Context(), workspaceID); err != nil {
				return err
			}
			for _, u := range []*db.User{owner, member, stranger} {
				m, err := q.GetWorkspaceMember(
					t.Context(),
					&db.GetWorkspaceMemberParams{WorkspaceID: workspaceID, UserID: u.ID},
				)
				if err == nil {
					roles[u.ID] = m.RoleName
				}
			}
			return nil
		}))
		return ownerID, roles
	}

	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(transfer(stranger.ID)),
		"a user who is not a member cannot be made owner")
	ownerID, roles := state()
	assert.Equal(t, owner.ID, ownerID, "a refused transfer keeps the owner")
	assert.Equal(t, map[string]string{owner.ID: "owner", member.ID: "editor"}, roles,
		"a refused transfer changes no role")

	require.NoError(t, transfer(member.ID))
	ownerID, roles = state()
	assert.Equal(t, member.ID, ownerID, "a member takes over")
	assert.Equal(t, map[string]string{owner.ID: "admin", member.ID: "owner"}, roles,
		"the old owner steps down to admin")
}
