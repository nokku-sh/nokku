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

// Settings that name no daemon defaults read as the built-in ones.
func TestWorkspaceReadsBuiltInDaemonDefaults(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		_, err := q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{Settings: &nokkuv1.WorkspaceSettings{}})
		return err
	})

	member := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	got, err := nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL, header("Authorization", "Bearer "+member)).
		GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
	require.NoError(t, err)
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
