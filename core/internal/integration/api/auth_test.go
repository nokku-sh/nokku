//go:build integration

package api_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// The name was once kept from boot, the login page showed the old one.
func TestLoginPageFollowsARename(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	before, err := workspaceName(wsCtx(t), cfg.Conn)
	require.NoError(t, err)
	workspaces := nokkuv1connect.NewWorkspaceServiceClient(
		clientOn(
			srv,
			header(
				"Authorization",
				"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
			),
		),
	)
	rename := func(name string) {
		t.Helper()
		_, err := workspaces.UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{Name: &name}))
		require.NoError(t, err)
	}
	// Other tests share the workspace.
	defer rename(before)

	renamed := uniq("renamed")
	rename(renamed)
	auth := nokkuv1connect.NewAuthServiceClient(clientOn(srv))
	options, err := auth.GetLoginOptions(t.Context(), &nokkuv1.GetLoginOptionsRequest{})
	require.NoError(t, err)
	assert.Equal(t, renamed, options.GetWorkspaceName())
}

// A sign-in link works once. No mail goes out, so the link comes from iam.
func TestMagicLinkSignIn(t *testing.T) {
	cfg, srv := newTestAPI(t)
	u := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	auth := nokkuv1connect.NewAuthServiceClient(clientOn(srv))

	options, err := auth.GetLoginOptions(t.Context(), &nokkuv1.GetLoginOptionsRequest{})
	require.NoError(t, err)
	assert.False(t, options.GetMagicLink(), "no mail, no links on the login page")
	assert.False(t, options.GetEmailConfigured())
	assert.True(t, options.GetPasskey())
	name, err := workspaceName(wsCtx(t), cfg.Conn)
	require.NoError(t, err)
	assert.Equal(t, name, options.GetWorkspaceName())

	_, err = auth.RequestMagicLink(t.Context(), &nokkuv1.RequestMagicLinkRequest{Email: &u.Email})
	require.NoError(t, err, "a request without mail still answers OK")

	link, err := cfg.IAM.IssueBootstrapLink(wsCtx(t), u)
	require.NoError(t, err)
	_, token, _ := strings.Cut(link, "token=")
	ctx, info := connect.NewClientContext(t.Context())
	got, err := auth.ConsumeMagicLink(ctx, &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.GetUser().GetId())
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER, got.GetUser().GetRole())
	assert.Contains(t, info.ResponseHeader().Get("Set-Cookie"), sessionCookie+"=", "the sign-in sets a session")

	_, err = auth.ConsumeMagicLink(t.Context(), &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "a spent link: %v", err)
}

// Removing a remembered device forgets it, and its cookie never signs in.
func TestRememberedDeviceShowsInTheSessionsList(t *testing.T) {
	cfg, srv := newTestAPI(t)
	u := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	link, err := cfg.IAM.IssueBootstrapLink(wsCtx(t), u)
	require.NoError(t, err)
	_, token, _ := strings.Cut(link, "token=")

	auth := nokkuv1connect.NewAuthServiceClient(clientOn(srv))
	ctx, info := connect.NewClientContext(t.Context())
	_, err = auth.ConsumeMagicLink(ctx, &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	require.NoError(t, err)
	cookies := map[string]string{}
	for _, line := range info.ResponseHeader().Values("Set-Cookie") {
		name, rest, _ := strings.Cut(line, "=")
		cookies[name], _, _ = strings.Cut(rest, ";")
	}
	require.NotEmpty(t, cookies[sessionCookie])
	var deviceCookie string
	for name, value := range cookies {
		if strings.HasPrefix(name, cookieNamed("nokku_device_")) {
			deviceCookie = value
		}
	}
	require.NotEmpty(t, deviceCookie, "a new browser gets the device cookie")

	account := func(bearer string) nokkuv1connect.AccountServiceClient {
		return nokkuv1connect.NewAccountServiceClient(
			clientOn(srv, header("Authorization", "Bearer "+bearer)),
		)
	}
	kinds := func() map[string]string {
		t.Helper()
		res, err := account(
			cookies[sessionCookie],
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

	_, err = account(deviceCookie).ListAccountSessions(t.Context(), &nokkuv1.ListAccountSessionsRequest{})
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the device cookie signed in: %v", err)

	_, err = account(
		cookies[sessionCookie],
	).RemoveSession(t.Context(), &nokkuv1.RemoveSessionRequest{Id: new(listed["device"])})
	require.NoError(t, err)
	listed = kinds()
	assert.Contains(t, listed, "user", "forgetting a device ended the session")
	assert.NotContains(t, listed, "device")
}

// The audit log tells a deactivated account from an address nobody has.
func TestMagicLinkToAnInactiveAccountIsAudited(t *testing.T) {
	base, _ := newTestAPI(t)
	cfg, _, _ := mailServer(t, base)
	u := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	inWorkspace(t, cfg, testWorkspace.ID, func(q *db.Queries) error {
		return q.SetUserActive(t.Context(), &db.SetUserActiveParams{ID: u.ID, Active: false})
	})

	cfg.IAM.RequestMagicLink(wsCtx(t), u.Email)

	assert.Eventually(t, func() bool {
		var rows []*db.ListAuditLogsRow
		err := cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(
				t.Context(),
				&db.ListAuditLogsParams{Actions: []string{"LoginDenied"}, Limit: 1000},
			)
			return err
		})
		return err == nil && slices.ContainsFunc(rows, func(r *db.ListAuditLogsRow) bool {
			return r.ActorName == u.Email && strings.Contains(string(r.Details), "inactive account")
		})
	}, 5*time.Second, 20*time.Millisecond, "no denied login names the inactive account")
}
