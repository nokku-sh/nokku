package api

import (
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/db"
)

// A sign-in link works once, on the host it was made for, and sets the
// session cookie. The test server sends no mail, so the link comes from iam.
func TestMagicLinkSignIn(t *testing.T) {
	cfg, srv := newTestAPI(t)
	u := seedUser(t, cfg, seedWorkspace(t, cfg), db.RoleViewer)
	auth := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL)

	options, err := auth.GetLoginOptions(t.Context(), &nokkuv1.GetLoginOptionsRequest{})
	require.NoError(t, err)
	assert.False(t, options.GetMagicLink(), "no mail, no links on the login page")
	assert.True(t, options.GetPasskey())
	assert.Equal(t, cfg.Tenant.Single().Name, options.GetWorkspaceName())

	_, err = auth.RequestMagicLink(t.Context(), &nokkuv1.RequestMagicLinkRequest{Email: &u.Email})
	require.NoError(t, err, "a request without mail still answers OK")

	link, err := cfg.IAM.IssueBootstrapLink(wsCtx(t, cfg), u)
	require.NoError(t, err)
	_, token, _ := strings.Cut(link, "token=")
	ctx, info := connect.NewClientContext(t.Context())
	got, err := auth.ConsumeMagicLink(ctx, &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.GetUser().GetId())
	assert.Equal(t, "viewer", got.GetUser().GetRole())
	assert.Contains(t, info.ResponseHeader().Get("Set-Cookie"), "nokku_session=", "the sign-in sets a session")

	_, err = auth.ConsumeMagicLink(t.Context(), &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "a spent link: %v", err)
}
