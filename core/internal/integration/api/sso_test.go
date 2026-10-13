//go:build integration

package api_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

// A provider and the SCIM tokens decide who signs in as anyone. An admin who could change them could become owner.
func TestIdentitySettingsNeedTheOwner(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ctx := t.Context()
	ws := seedWorkspace(t, cfg)
	owner := header("Authorization", "Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER))
	admin := header("Authorization", "Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))

	sso := nokkuv1connect.NewSSOServiceClient(srv.Client(), srv.URL, admin)
	scim := nokkuv1connect.NewSCIMServiceClient(srv.Client(), srv.URL, admin)
	provider := &nokkuv1.PutSSOProviderRequest{
		ProviderId:   new("mine"),
		Name:         new("mine"),
		Enabled:      new(true),
		IssuerUrl:    new("https://idp.evil.example"),
		ClientId:     new("nokku"),
		ClientSecret: new("s3cret"),
	}
	for what, call := range map[string]func() error{
		"set a provider": func() error {
			_, err := sso.PutSSOProvider(ctx, provider)
			return err
		},
		"drop a provider": func() error {
			_, err := sso.DeleteSSOProvider(ctx, &nokkuv1.DeleteSSOProviderRequest{ProviderId: new("mine")})
			return err
		},
		"issue a SCIM token": func() error {
			_, err := scim.CreateSCIMToken(ctx, &nokkuv1.CreateSCIMTokenRequest{Label: new("idp")})
			return err
		},
		"revoke a SCIM token": func() error {
			_, err := scim.DeleteSCIMToken(ctx, &nokkuv1.DeleteSCIMTokenRequest{Id: &ws})
			return err
		},
	} {
		var refused *connect.Error
		if assert.ErrorAs(t, call(), &refused, "an admin may %s", what) {
			assert.Equal(t, connect.CodePermissionDenied, refused.Code(), "an admin may %s", what)
			assert.Equal(t, "you don't have permission to do that", refused.Message(), "an admin may %s", what)
		}
	}
	_, err := sso.ListSSOProviders(ctx, &nokkuv1.ListSSOProvidersRequest{})
	require.NoError(t, err, "an admin still reads the providers")
	_, err = scim.ListSCIMTokens(ctx, &nokkuv1.ListSCIMTokensRequest{})
	require.NoError(t, err, "an admin still reads the SCIM tokens")

	// The owner stores it, and the login page offers it right away.
	ownerSSO := nokkuv1connect.NewSSOServiceClient(srv.Client(), srv.URL, owner)
	stored, err := ownerSSO.PutSSOProvider(ctx, provider)
	require.NoError(t, err)
	assert.Equal(t, "mine", stored.GetProvider().GetProviderId())
	assert.Equal(t, "https://idp.evil.example", stored.GetProvider().GetIssuerUrl())

	options, err := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL).
		GetLoginOptions(ctx, &nokkuv1.GetLoginOptionsRequest{})
	require.NoError(t, err)
	var ids []string
	for _, p := range options.GetProviders() {
		ids = append(ids, p.GetProviderId())
	}
	assert.Contains(t, ids, "mine")

	_, err = ownerSSO.DeleteSSOProvider(ctx, &nokkuv1.DeleteSSOProviderRequest{ProviderId: new("mine")})
	require.NoError(t, err)
	_, err = ownerSSO.DeleteSSOProvider(ctx, &nokkuv1.DeleteSSOProviderRequest{ProviderId: new("mine")})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "deleting it twice: %v", err)
}

// Only the hosted service insists on TLS, a lab runs its provider without.
func TestSelfHostTakesAProviderOnPlainHTTP(t *testing.T) {
	cfg, srv := newTestAPI(t)
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	sso := nokkuv1connect.NewSSOServiceClient(srv.Client(), srv.URL, owner)
	const issuer = "http://keycloak.lab:8080/realms/master"
	stored, err := sso.PutSSOProvider(t.Context(), &nokkuv1.PutSSOProviderRequest{
		ProviderId: new("lab"), Name: new("Lab"), Enabled: new(true), IssuerUrl: new(issuer),
		ClientId: new("nokku"), ClientSecret: new("s3cret"),
	})
	require.NoError(t, err)
	assert.Equal(t, issuer, stored.GetProvider().GetIssuerUrl())

	// The stored secret stays with its issuer.
	moved := &nokkuv1.PutSSOProviderRequest{
		ProviderId: new("lab"), Name: new("Lab"), Enabled: new(true), IssuerUrl: new("http://other.lab:8080"),
		ClientId: new("nokku"),
	}
	_, err = sso.PutSSOProvider(t.Context(), moved)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "a new issuer without the secret: %v", err)
	moved.ClientSecret = new("fresh")
	_, err = sso.PutSSOProvider(t.Context(), moved)
	require.NoError(t, err, "a new issuer with its secret")
	moved.ClientSecret = nil
	_, err = sso.PutSSOProvider(t.Context(), moved)
	require.NoError(t, err, "the same issuer keeps the stored secret")

	_, err = sso.DeleteSSOProvider(t.Context(), &nokkuv1.DeleteSSOProviderRequest{ProviderId: new("lab")})
	require.NoError(t, err)
}

// Enforcing SSO is a paid feature, and the test workspace is on Community.
func TestEnforceSSOIsGated(t *testing.T) {
	cfg, srv := newTestAPI(t)
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	_, err := nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL, owner).
		UpdateWorkspace(t.Context(), &nokkuv1.UpdateWorkspaceRequest{
			Settings: &nokkuv1.WorkspaceSettings{EnforceSso: new(true)},
		})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "got %v", err)
}
