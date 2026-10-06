package api

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

// The provider, the domains and the SCIM tokens decide who signs in as an
// account under the workspace's domains, the owner's included. An admin who
// could change them could become the owner.
func TestIdentitySettingsNeedTheOwner(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ctx := t.Context()
	ws := seedWorkspace(t, cfg)
	ownerID, err := cfg.Conn.Sys().GetWorkspaceOwner(ctx, ws)
	require.NoError(t, err)
	_, ownerToken, err := cfg.IAM.IssueSession(ctx, iam.SessionParams{
		SubjectID: ownerID,
		Kind:      actor.KindUser,
		Method:    iam.MethodPassword,
	})
	require.NoError(t, err)
	owner := header("Authorization", "Bearer "+ownerToken)
	admin := header("Authorization", "Bearer "+seedMember(t, cfg, ws, db.RoleAdmin))

	sso := nokkuv1connect.NewSSOServiceClient(srv.Client(), srv.URL, admin)
	domains := nokkuv1connect.NewWorkspaceDomainServiceClient(srv.Client(), srv.URL, admin)
	scim := nokkuv1connect.NewSCIMServiceClient(srv.Client(), srv.URL, admin)

	domain := new("acme.test")
	provider := &nokkuv1.UpdateSSOProviderRequest{
		WorkspaceId: &ws,
		Method:      new("oidc"),
		Name:        new("mine"),
		IsActive:    new(true),
		Config:      &nokkuv1.SSOConfig{IssuerUrl: new("https://idp.evil.example"), ClientId: new("nokku")},
	}
	for what, call := range map[string]func() error{
		"set the provider": func() error {
			_, err := sso.UpdateSSOProvider(ctx, provider)
			return err
		},
		"add a domain": func() error {
			_, err := domains.CreateWorkspaceDomain(
				ctx,
				&nokkuv1.CreateWorkspaceDomainRequest{WorkspaceId: &ws, Domain: domain},
			)
			return err
		},
		"verify a domain": func() error {
			_, err := domains.VerifyWorkspaceDomain(
				ctx,
				&nokkuv1.VerifyWorkspaceDomainRequest{WorkspaceId: &ws, Domain: domain},
			)
			return err
		},
		"drop a domain": func() error {
			_, err := domains.DeleteWorkspaceDomain(
				ctx,
				&nokkuv1.DeleteWorkspaceDomainRequest{WorkspaceId: &ws, Domain: domain},
			)
			return err
		},
		"reset a domain": func() error {
			_, err := domains.RegenerateWorkspaceDomainToken(
				ctx,
				&nokkuv1.RegenerateWorkspaceDomainTokenRequest{WorkspaceId: &ws, Domain: domain},
			)
			return err
		},
		"issue a SCIM token": func() error {
			_, err := scim.CreateSCIMToken(ctx, &nokkuv1.CreateSCIMTokenRequest{WorkspaceId: &ws, Label: new("idp")})
			return err
		},
		"revoke a SCIM token": func() error {
			_, err := scim.DeleteSCIMToken(ctx, &nokkuv1.DeleteSCIMTokenRequest{WorkspaceId: &ws, TokenId: &ws})
			return err
		},
	} {
		// The plan check answers with the same code, the message tells them apart.
		var refused *connect.Error
		if assert.ErrorAs(t, call(), &refused, "an admin may %s", what) {
			assert.Equal(t, connect.CodePermissionDenied, refused.Code(), "an admin may %s", what)
			assert.Equal(t, errPermissionDenied.Message(), refused.Message(), "an admin may %s", what)
		}
	}

	_, err = sso.GetSSOProvider(ctx, &nokkuv1.GetSSOProviderRequest{WorkspaceId: &ws})
	require.NoError(t, err, "an admin still reads the provider")
	_, err = domains.ListWorkspaceDomains(ctx, &nokkuv1.ListWorkspaceDomainsRequest{WorkspaceId: &ws})
	require.NoError(t, err, "an admin still reads the domains")
	_, err = scim.ListSCIMTokens(ctx, &nokkuv1.ListSCIMTokensRequest{WorkspaceId: &ws})
	require.NoError(t, err, "an admin still reads the SCIM tokens")

	// The owner gets as far as the handler, which wants a verified domain.
	_, err = nokkuv1connect.NewSSOServiceClient(srv.Client(), srv.URL, owner).UpdateSSOProvider(ctx, provider)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "the owner: %v", err)
}
