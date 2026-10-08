package api

import (
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"
)

// The name is read from the row. It used to be kept from boot, so the login
// page showed the old one until a restart.
func TestLoginPageFollowsARename(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	before, err := workspaceName(wsCtx(t, cfg), cfg.Conn)
	require.NoError(t, err)
	workspaces := nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL,
		header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)))
	rename := func(name string) {
		t.Helper()
		_, err := workspaces.UpdateWorkspace(t.Context(), &nokkuv1.UpdateWorkspaceRequest{Name: &name})
		require.NoError(t, err)
	}
	// Other tests share the workspace.
	defer rename(before)

	renamed := uniq("renamed")
	rename(renamed)
	auth := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL)
	options, err := auth.GetLoginOptions(t.Context(), &nokkuv1.GetLoginOptionsRequest{})
	require.NoError(t, err)
	assert.Equal(t, renamed, options.GetWorkspaceName())
}

// A sign-in link works once, on the host it was made for, and sets the
// session cookie. The test server sends no mail, so the link comes from iam.
func TestMagicLinkSignIn(t *testing.T) {
	cfg, srv := newTestAPI(t)
	u := seedUser(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	auth := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL)

	options, err := auth.GetLoginOptions(t.Context(), &nokkuv1.GetLoginOptionsRequest{})
	require.NoError(t, err)
	assert.False(t, options.GetMagicLink(), "no mail, no links on the login page")
	assert.True(t, options.GetPasskey())
	name, err := workspaceName(wsCtx(t, cfg), cfg.Conn)
	require.NoError(t, err)
	assert.Equal(t, name, options.GetWorkspaceName())

	_, err = auth.RequestMagicLink(t.Context(), &nokkuv1.RequestMagicLinkRequest{Email: &u.Email})
	require.NoError(t, err, "a request without mail still answers OK")

	link, err := cfg.IAM.IssueBootstrapLink(wsCtx(t, cfg), u)
	require.NoError(t, err)
	_, token, _ := strings.Cut(link, "token=")
	ctx, info := connect.NewClientContext(t.Context())
	got, err := auth.ConsumeMagicLink(ctx, &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.GetUser().GetId())
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER, got.GetUser().GetRole())
	assert.Contains(t, info.ResponseHeader().Get("Set-Cookie"), "nokku_session=", "the sign-in sets a session")

	_, err = auth.ConsumeMagicLink(t.Context(), &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "a spent link: %v", err)
}

// The list under "where you're signed in" shows sessions and remembered
// devices. Removing a device forgets it, and its cookie never signs in.
func TestRememberedDeviceShowsInTheSessionsList(t *testing.T) {
	cfg, srv := newTestAPI(t)
	u := seedUser(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	link, err := cfg.IAM.IssueBootstrapLink(wsCtx(t, cfg), u)
	require.NoError(t, err)
	_, token, _ := strings.Cut(link, "token=")

	auth := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL)
	ctx, info := connect.NewClientContext(t.Context())
	_, err = auth.ConsumeMagicLink(ctx, &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	require.NoError(t, err)
	cookies := map[string]string{}
	for _, line := range info.ResponseHeader().Values("Set-Cookie") {
		name, rest, _ := strings.Cut(line, "=")
		cookies[name], _, _ = strings.Cut(rest, ";")
	}
	require.NotEmpty(t, cookies["nokku_session"])
	require.NotEmpty(t, cookies["nokku_device"], "a new browser gets the device cookie")

	account := func(bearer string) nokkuv1connect.AccountServiceClient {
		return nokkuv1connect.NewAccountServiceClient(srv.Client(), srv.URL, header("Authorization", "Bearer "+bearer))
	}
	kinds := func() map[string]string {
		t.Helper()
		res, err := account(
			cookies["nokku_session"],
		).ListAccountSessions(t.Context(), &nokkuv1.ListAccountSessionsRequest{})
		require.NoError(t, err)
		out := map[string]string{}
		for _, s := range res.GetSessions() {
			out[s.GetKind()] = s.GetId()
		}
		return out
	}
	listed := kinds()
	require.Contains(t, listed, "user")
	require.Contains(t, listed, "device")

	_, err = account(cookies["nokku_device"]).ListAccountSessions(t.Context(), &nokkuv1.ListAccountSessionsRequest{})
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the device cookie signed in: %v", err)

	_, err = account(
		cookies["nokku_session"],
	).RemoveSession(t.Context(), &nokkuv1.RemoveSessionRequest{Id: new(listed["device"])})
	require.NoError(t, err)
	listed = kinds()
	assert.Contains(t, listed, "user", "forgetting a device ended the session")
	assert.NotContains(t, listed, "device")
}
