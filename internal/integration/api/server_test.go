//go:build integration

package api_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/db"
)

// A public RPC must not buffer a body of any size before it is even validated.
func TestRequestSizeLimit(t *testing.T) {
	_, srv := newTestAPI(t)
	_, err := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL).
		ConsumeMagicLink(t.Context(), &nokkuv1.ConsumeMagicLinkRequest{
			Token: new(strings.Repeat("x", maxMessageBytes+1)),
		})
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "got %v", err)
}

// The audit webhook secret signs events to the customer's SIEM. Only the owner may read it back.
func TestWorkspaceHidesWebhookFromMembers(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		_, err := q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{
			Settings: &nokkuv1.WorkspaceSettings{
				AuditWebhookUrl:    new("https://siem.example/hook"),
				AuditWebhookSecret: new("s3cret"),
			},
		})
		return err
	})

	client := func(role nokkuv1.WorkspaceRole) nokkuv1connect.WorkspaceServiceClient {
		return nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL,
			header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, role)))
	}

	for _, role := range []nokkuv1.WorkspaceRole{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN} {
		got, err := client(role).GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
		require.NoError(t, err)
		assert.Empty(t, got.GetWorkspace().GetSettings().GetAuditWebhookSecret(), "%s reads the secret", role)
		assert.Empty(t, got.GetWorkspace().GetSettings().GetAuditWebhookUrl(), "%s reads the url", role)
	}

	got, err := client(
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER,
	).GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
	require.NoError(t, err)
	assert.Equal(t, "s3cret", got.GetWorkspace().GetSettings().GetAuditWebhookSecret())
	assert.True(t,
		proto.Equal(db.DefaultDaemonConfig(), got.GetWorkspace().GetSettings().GetDefaultDaemonConfig()),
		"daemon defaults nobody set read as the built-in ones")
}

// The API needs no client library: a procedure is a JSON POST to its path.
func TestPlainJSONCall(t *testing.T) {
	_, srv := newTestAPI(t)
	resp, err := srv.Client().Post(
		srv.URL+nokkuv1connect.AuthServiceConsumeMagicLinkProcedure,
		"application/json",
		strings.NewReader(`{"token":"not-a-link"}`),
	)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), `"code":"unauthenticated"`)
}

// A newer client may call a service this build does not have. It must get a 404, not the SPA's index page.
func TestUnknownServiceIsNotFound(t *testing.T) {
	_, srv := newTestAPI(t)
	resp, err := srv.Client().Post(srv.URL+"/nokku.v1.FutureService/Do", "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
