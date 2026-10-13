//go:build integration

package api_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

func TestTransferOwnership(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := seedWorkspace(t, cfg)
	owner := seedOwner(t, cfg)
	member := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	stranger := seedUser(t, cfg, seedOtherWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	workspaces := nokkuv1connect.NewWorkspaceServiceClient(
		srv.Client(), srv.URL, header("Authorization", "Bearer "+sessionFor(t, cfg, owner)),
	)
	transfer := func(to string) error {
		_, err := workspaces.TransferOwnership(t.Context(), &nokkuv1.TransferOwnershipRequest{NewOwnerId: &to})
		return err
	}
	role := func(u *db.User) nokkuv1.WorkspaceRole {
		got, err := cfg.Conn.Sys().GetUser(t.Context(), u.ID)
		require.NoError(t, err)
		return got.Role
	}

	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(transfer(stranger.ID)),
		"a user of another workspace cannot be made owner")
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER, role(owner), "a refused transfer keeps the owner")
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, role(member), "a refused transfer changes no role")

	require.NoError(t, transfer(member.ID))
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER, role(member), "a member takes over")
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN, role(owner), "the old owner steps down to admin")
	assert.Equal(t, member.ID, seedOwner(t, cfg).ID)
}

// A write to the owner row after the new owner joined puts it behind that row. One statement that swaps both roles
// then makes the new owner first and trips the index that allows a single owner.
func TestTransferOwnershipAfterTheOwnerRowMoved(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := seedWorkspace(t, cfg)
	member := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	owner := seedOwner(t, cfg)
	inWorkspace(t, cfg, ws, func(q *db.Queries) error {
		_, err := q.UpdateUser(t.Context(), &db.UpdateUserParams{ID: owner.ID, Name: new("renamed")})
		return err
	})

	workspaces := nokkuv1connect.NewWorkspaceServiceClient(
		srv.Client(), srv.URL, header("Authorization", "Bearer "+sessionFor(t, cfg, owner)),
	)
	_, err := workspaces.TransferOwnership(t.Context(), &nokkuv1.TransferOwnershipRequest{NewOwnerId: &member.ID})
	require.NoError(t, err)
	assert.Equal(t, member.ID, seedOwner(t, cfg).ID)
}

func TestDeleteUserRemovesTheAvatar(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := seedWorkspace(t, cfg)
	user := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	avatar := storage.AvatarPath(user.ID)
	_, err := cfg.Storage.Store(t.Context(), avatar, []byte("jpeg"), storage.StoreOptions{ContentType: "image/jpeg"})
	require.NoError(t, err)

	admin := nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL,
		header("Authorization", "Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)))
	_, err = admin.DeleteUser(t.Context(), &nokkuv1.DeleteUserRequest{UserId: &user.ID})
	require.NoError(t, err)

	_, err = cfg.Storage.Reader(t.Context(), avatar)
	assert.Error(t, err, "the photo outlived the account")
}

// Admins manage users below them and never the owner or themselves.
func TestManageUsers(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := seedWorkspace(t, cfg)
	owner := seedOwner(t, cfg)
	admin := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	viewer := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	workspaces := nokkuv1connect.NewWorkspaceServiceClient(
		srv.Client(), srv.URL, header("Authorization", "Bearer "+sessionFor(t, cfg, admin)),
	)

	_, err := workspaces.UpdateUserRole(t.Context(), &nokkuv1.UpdateUserRoleRequest{
		UserId: &viewer.ID, Role: new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR),
	})
	require.NoError(t, err)
	got, err := workspaces.GetUser(t.Context(), &nokkuv1.GetUserRequest{UserId: &viewer.ID})
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, got.GetUser().GetRole())

	_, err = workspaces.SetUserActive(t.Context(), &nokkuv1.SetUserActiveRequest{UserId: &owner.ID, Active: new(false)})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "an admin switched the owner off: %v", err)
	_, err = workspaces.SetUserActive(t.Context(), &nokkuv1.SetUserActiveRequest{UserId: &admin.ID, Active: new(false)})
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "an admin switched themselves off: %v", err)

	viewerToken := sessionFor(t, cfg, viewer)
	_, err = workspaces.SetUserActive(
		t.Context(),
		&nokkuv1.SetUserActiveRequest{UserId: &viewer.ID, Active: new(false)},
	)
	require.NoError(t, err)
	_, _, err = cfg.IAM.AuthenticateToken(wsCtx(t, cfg), viewerToken)
	require.Error(t, err, "a deactivated user kept their session")

	users, err := workspaces.ListUsers(
		t.Context(),
		&nokkuv1.ListUsersRequest{Limit: new(int32(100)), Role: new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)},
	)
	require.NoError(t, err)
	require.Len(t, users.GetUsers(), 1, "one owner")
	assert.Equal(t, owner.ID, users.GetUsers()[0].GetId())

	_, err = workspaces.DeleteUser(t.Context(), &nokkuv1.DeleteUserRequest{UserId: &viewer.ID})
	require.NoError(t, err)
	_, err = workspaces.GetUser(t.Context(), &nokkuv1.GetUserRequest{UserId: &viewer.ID})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

// A self-hosted server keeps its workspace, and signup is for the hosted one.
func TestSelfHostHasOneWorkspace(t *testing.T) {
	cfg, srv := newTestAPI(t)
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	_, err := nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL, owner).
		DeleteWorkspace(t.Context(), &nokkuv1.DeleteWorkspaceRequest{})
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "got %v", err)

	_, err = nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL).
		CreateWorkspace(t.Context(), &nokkuv1.CreateWorkspaceRequest{
			Slug: new("acme"), Name: new("Acme"), OwnerEmail: new("o@acme.test"),
		})
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "got %v", err)
}

func TestSubscribeChangesHearsAWrite(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := seedWorkspace(t, cfg)
	ctx, call := connect.NewClientContext(t.Context())
	call.RequestHeader().
		Set("Authorization", "Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER))
	stream, err := nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL).
		SubscribeChanges(ctx, &nokkuv1.SubscribeChangesRequest{})
	require.NoError(t, err)
	defer stream.Close()

	require.True(t, stream.Receive(), "the first message opens the stream: %v", stream.Err())
	assert.False(t, stream.Msg().GetEverything())

	inWorkspace(t, cfg, ws, func(q *db.Queries) error {
		_, err := q.CreateTeam(t.Context(), &db.CreateTeamParams{Name: uniq("team"), Tags: []string{}})
		return err
	})
	require.True(t, stream.Receive(), "a write is heard: %v", stream.Err())
	assert.True(t, stream.Msg().GetEverything())
}

func TestSubscribeChangesNeedsASession(t *testing.T) {
	_, srv := newTestAPI(t)
	stream, err := nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL).
		SubscribeChanges(t.Context(), &nokkuv1.SubscribeChangesRequest{})
	require.NoError(t, err)
	defer stream.Close()

	assert.False(t, stream.Receive())
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(stream.Err()))
}
