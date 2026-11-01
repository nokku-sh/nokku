//go:build integration

package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

func TestUpdateTeamTagsChangeOnlyWhenNamed(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	editor := nokkuv1connect.NewTeamServiceClient(
		clientOn(
			srv,
			header(
				"Authorization",
				"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR),
			),
		),
	)

	created, err := editor.CreateTeam(t.Context(), &nokkuv1.CreateTeamRequest{
		Name: new(uniq("platform")),
		Tags: []string{"prod"},
	})
	require.NoError(t, err)
	id, name := created.GetTeam().GetId(), created.GetTeam().GetName()

	updated, err := editor.UpdateTeam(t.Context(), masked(&nokkuv1.UpdateTeamRequest{Id: &id, Description: new("x")}))
	require.NoError(t, err)
	assert.Equal(t, []string{"prod"}, updated.GetTeam().GetTags(), "tags the update leaves out stay")
	assert.Equal(t, name, updated.GetTeam().GetName(), "unset fields stay as they are")

	updated, err = editor.UpdateTeam(t.Context(), &nokkuv1.UpdateTeamRequest{
		Id:         &id,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tags"}},
	})
	require.NoError(t, err)
	assert.Empty(t, updated.GetTeam().GetTags(), "naming the tags with none clears them")
}
