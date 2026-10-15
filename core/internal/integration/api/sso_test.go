//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

// fakeIssuer serves a discovery document under any path, so each path is an issuer of its own.
func fakeIssuer(t *testing.T) *httptest.Server {
	t.Helper()
	const wellKnown = "/.well-known/openid-configuration"
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer, ok := strings.CutSuffix(r.URL.Path, wellKnown)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 ts.URL + issuer,
			"authorization_endpoint": ts.URL + issuer + "/authorize",
			"token_endpoint":         ts.URL + issuer + "/token",
			"jwks_uri":               ts.URL + issuer + "/jwks",
		})
	}))
	t.Cleanup(ts.Close)
	return ts
}

// A provider and the SCIM tokens decide who signs in as anyone. An admin who could change them could become owner.
func TestIdentitySettingsNeedTheOwner(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ctx := t.Context()
	ws := seedWorkspace(t, cfg)
	owner := header("Authorization", "Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER))
	admin := header("Authorization", "Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))

	sso := nokkuv1connect.NewSSOServiceClient(srv.Client(), srv.URL, admin)
	scim := nokkuv1connect.NewSCIMServiceClient(srv.Client(), srv.URL, admin)
	issuer := fakeIssuer(t).URL + "/evil"
	provider := &nokkuv1.PutSSOProviderRequest{
		ProviderId:   new("mine"),
		Name:         new("mine"),
		Enabled:      new(true),
		IssuerUrl:    new(issuer),
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
	assert.Equal(t, issuer, stored.GetProvider().GetIssuerUrl())

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
	lab := fakeIssuer(t).URL
	issuer := lab + "/realms/master"
	stored, err := sso.PutSSOProvider(t.Context(), &nokkuv1.PutSSOProviderRequest{
		ProviderId: new("lab"), Name: new("Lab"), Enabled: new(true), IssuerUrl: new(issuer),
		ClientId: new("nokku"), ClientSecret: new("s3cret"),
	})
	require.NoError(t, err)
	assert.Equal(t, issuer, stored.GetProvider().GetIssuerUrl())

	// The stored secret stays with its issuer.
	moved := &nokkuv1.PutSSOProviderRequest{
		ProviderId: new("lab"), Name: new("Lab"), Enabled: new(true), IssuerUrl: new(lab + "/realms/other"),
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

// A typo in the issuer fails on save. A provider that is down later still saves, so it can be turned off.
func TestNewIssuerMustAnswer(t *testing.T) {
	cfg, srv := newTestAPI(t)
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	sso := nokkuv1connect.NewSSOServiceClient(srv.Client(), srv.URL, owner)
	idp := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(idp.Close)

	typo := &nokkuv1.PutSSOProviderRequest{
		ProviderId: new("typo"), Name: new("Typo"), Enabled: new(true), IssuerUrl: new(idp.URL + "/realms/typo"),
		ClientId: new("nokku"), ClientSecret: new("s3cret"),
	}
	_, err := sso.PutSSOProvider(t.Context(), typo)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "an issuer without discovery: %v", err)

	gone := fakeIssuer(t)
	down := &nokkuv1.PutSSOProviderRequest{
		ProviderId: new("down"), Name: new("Down"), Enabled: new(true), IssuerUrl: new(gone.URL + "/realms/down"),
		ClientId: new("nokku"), ClientSecret: new("s3cret"),
	}
	_, err = sso.PutSSOProvider(t.Context(), down)
	require.NoError(t, err)
	gone.Close()
	down.Enabled, down.ClientSecret = new(false), nil
	_, err = sso.PutSSOProvider(t.Context(), down)
	require.NoError(t, err, "turning off a provider with the same issuer")

	_, err = sso.DeleteSSOProvider(t.Context(), &nokkuv1.DeleteSSOProviderRequest{ProviderId: new("down")})
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
