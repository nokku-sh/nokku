package api

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"
)

func TestUpdateServiceAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(srv.Client(), srv.URL, auth)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new("deploy"),
		Tags: []string{"ci"},
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()

	updated, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{
		Id:   &id,
		Tags: []string{"ci", "prod"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"ci", "prod"}, updated.GetServiceAccount().GetTags(), "tags must be saved")
	assert.Equal(
		t,
		created.GetServiceAccount().GetName(),
		updated.GetServiceAccount().GetName(),
		"unset fields stay as they are",
	)

	cleared, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{
		Id: &id,
	})
	require.NoError(t, err)
	assert.Empty(t, cleared.GetServiceAccount().GetTags(), "an update replaces the tags, the last one can go")
}

func TestServiceAccountRole(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(srv.Client(), srv.URL, auth)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("sa")),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, created.GetServiceAccount().GetRole(),
		"no role is the member")

	update := func(role *nokkuv1.WorkspaceRole) (nokkuv1.WorkspaceRole, error) {
		res, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{Id: &id, Role: role})
		return res.GetServiceAccount().GetRole(), err
	}
	got, err := update(new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, got)

	got, err = update(nil)
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, got, "an update without a role keeps it")

	got, err = update(new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER))
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, got, "the member can be named")

	_, err = update(new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"the editor is the most a service account can be")
}
