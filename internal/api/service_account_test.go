package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/db"
)

func TestUpdateServiceAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	auth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleAdmin))
	client := nokkuv1connect.NewServiceAccountServiceClient(srv.Client(), srv.URL, auth)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		WorkspaceId: &workspaceID,
		Name:        new("deploy"),
		Tags:        []string{"ci"},
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()

	updated, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{
		WorkspaceId: &workspaceID,
		Id:          &id,
		Tags:        []string{"ci", "prod"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"ci", "prod"}, updated.GetServiceAccount().GetTags(), "tags must be saved")
	assert.Equal(t, "deploy", updated.GetServiceAccount().GetName(), "unset fields stay as they are")

	cleared, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{
		WorkspaceId: &workspaceID,
		Id:          &id,
	})
	require.NoError(t, err)
	assert.Empty(t, cleared.GetServiceAccount().GetTags(), "an update replaces the tags, the last one can go")
}
