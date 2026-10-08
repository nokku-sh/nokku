//go:build integration

package api_test

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/db"
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

	// The table refuses it too, whatever a caller gets past the API.
	err = cfg.Conn.TenantTx(wsCtx(t, cfg), func(q *db.Queries) error {
		_, err := q.CreateServiceAccount(t.Context(), &db.CreateServiceAccountParams{
			Name: uniq("sa"),
			Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN,
		})
		return err
	})
	assert.Error(t, err, "the table took a service account above the editor")
}

// Rotating swaps the token and nothing else. The account keeps its id, so
// its grants and its audit trail stay with it.
func TestRotateServiceAccountToken(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(srv.Client(), srv.URL, auth)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name:           new(uniq("sa")),
		TokenExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()
	require.NotNil(t, created.GetServiceAccount().GetTokenExpiresAt())

	whoami := func(token string) (string, error) {
		res, err := nokkuv1connect.NewUtilServiceClient(
			srv.Client(), srv.URL, header("Authorization", "Bearer "+token),
		).Whoami(t.Context(), &nokkuv1.WhoamiRequest{})
		return res.GetSubjectId(), err
	}
	got, err := whoami(created.GetToken())
	require.NoError(t, err)
	require.Equal(t, id, got)

	rotated, err := client.RotateServiceAccountToken(t.Context(), &nokkuv1.RotateServiceAccountTokenRequest{Id: &id})
	require.NoError(t, err)
	assert.Equal(t, id, rotated.GetServiceAccount().GetId(), "the account must stay the same one")
	assert.Nil(t, rotated.GetServiceAccount().GetTokenExpiresAt(), "an expiry that is left out is cleared")

	_, err = whoami(created.GetToken())
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the old token still works, got %v", err)
	got, err = whoami(rotated.GetToken())
	require.NoError(t, err)
	assert.Equal(t, id, got, "the new token signs in as the same account")

	_, err = client.RotateServiceAccountToken(t.Context(), &nokkuv1.RotateServiceAccountTokenRequest{
		Id:             &id,
		TokenExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "an expiry in the past, got %v", err)
	_, err = whoami(rotated.GetToken())
	assert.NoError(t, err, "a refused rotation must leave the token alone")
}
