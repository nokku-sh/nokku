//go:build integration

package api_test

import (
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

func TestUpdateTeamReplacesTags(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	editor := nokkuv1connect.NewTeamServiceClient(
		connect.NewClient(
			connecthttp.NewTransport(srv.Client(), srv.URL),
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

	updated, err := editor.UpdateTeam(t.Context(), &nokkuv1.UpdateTeamRequest{Id: &id})
	require.NoError(t, err)
	assert.Empty(t, updated.GetTeam().GetTags(), "an update replaces the tags, the last one can go")
	assert.Equal(t, name, updated.GetTeam().GetName(), "unset fields stay as they are")
}
