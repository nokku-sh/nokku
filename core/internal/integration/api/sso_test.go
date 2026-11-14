//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// fakeIssuer serves discovery under any path, each path is its own issuer.
func fakeIssuer(t *testing.T) *httptest.Server {
	t.Helper()
	const wellKnown = "/.well-known/openid-configuration"
	var ts *httptest.Server
	ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if hosted {
		ts.StartTLS()
	} else {
		ts.Start()
	}
	t.Cleanup(ts.Close)
	return ts
}

// An admin who could change providers or SCIM tokens could become owner.
func TestIdentitySettingsNeedTheOwner(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ctx := t.Context()
	ws := testWorkspace.ID
	owner := header("Authorization", "Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER))
	admin := header("Authorization", "Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))

	sso := nokkuv1connect.NewSSOServiceClient(clientOn(srv, admin))
	scim := nokkuv1connect.NewSCIMServiceClient(
		clientOn(srv, admin),
	)
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
	ownerSSO := nokkuv1connect.NewSSOServiceClient(
		clientOn(srv, owner),
	)
	stored, err := ownerSSO.PutSSOProvider(ctx, provider)
	require.NoError(t, err)
	assert.Equal(t, "mine", stored.GetProvider().GetProviderId())
	assert.Equal(t, issuer, stored.GetProvider().GetIssuerUrl())

	options, err := nokkuv1connect.NewAuthServiceClient(clientOn(srv)).
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
	selfHostedOnly(t, "the hosted service refuses http")
	cfg, srv := newTestAPI(t)
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	sso := nokkuv1connect.NewSSOServiceClient(clientOn(srv, owner))
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

// A bad issuer fails on save, a provider that went down can be turned off.
func TestNewIssuerMustAnswer(t *testing.T) {
	cfg, srv := newTestAPI(t)
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	sso := nokkuv1connect.NewSSOServiceClient(clientOn(srv, owner))
	idp := httptest.NewTLSServer(http.NotFoundHandler())
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
	t.Cleanup(withoutAPlan(t, cfg))
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	_, err := nokkuv1connect.NewWorkspaceServiceClient(clientOn(srv, owner)).
		UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
			Settings: &nokkuv1.WorkspaceSettings{EnforceSso: new(true)},
		}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "got %v", err)
}

// A client may send back the whole workspace and name only what it changes.
func TestPlanGateReadsOnlyMaskedFields(t *testing.T) {
	cfg, srv := newTestAPI(t)
	t.Cleanup(withoutAPlan(t, cfg))
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	workspaces := nokkuv1connect.NewWorkspaceServiceClient(
		clientOn(srv, owner),
	)
	got, err := workspaces.GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
	require.NoError(t, err)

	updated, err := workspaces.UpdateWorkspace(t.Context(), &nokkuv1.UpdateWorkspaceRequest{
		Description: new(got.GetWorkspace().GetDescription()),
		Settings:    &nokkuv1.WorkspaceSettings{EnforceSso: new(true)},
		UpdateMask:  &fieldmaskpb.FieldMask{Paths: []string{"description"}},
	})
	require.NoError(t, err, "a gated field outside the mask refused the call")
	assert.False(t, updated.GetWorkspace().GetSettings().GetEnforceSso(), "a field outside the mask was stored")
}

// seedProvider is an enabled provider. Call it before saving what the test
// restores, so enforcement is off by the time it goes.
func seedProvider(t *testing.T, cfg *app.Config) {
	t.Helper()
	id := uniq("provider")
	_, err := cfg.IAM.PutSSOProvider(wsCtx(t), iam.SSOProvider{
		ProviderID: id, Name: "Seeded", Enabled: true,
		OIDC: iam.OIDCProvider{IssuerURL: "https://idp.test", ClientID: "nokku", ClientSecret: "s3cret"},
	})
	require.NoError(t, err)
	// The workspace is shared, the login page of later tests must not offer it.
	t.Cleanup(func() {
		ctx := actor.WithWorkspace(context.WithoutCancel(t.Context()), testWorkspace)
		require.NoError(t, cfg.IAM.DeleteSSOProvider(ctx, id))
	})
}

// Enforced SSO with no provider locks everyone but the owner out.
func TestEnforcedSSOKeepsAProvider(t *testing.T) {
	cfg, _ := newTestAPI(t)
	srv := enterpriseServer(t)
	var original *db.Workspace
	inWorkspace(t, cfg, testWorkspace.ID, func(q *db.Queries) (err error) {
		original, err = q.GetWorkspace(t.Context())
		return err
	})
	t.Cleanup(func() { restoreWorkspace(context.WithoutCancel(t.Context()), t, cfg, original) })

	owner := clientOn(srv, header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	))
	workspaces := nokkuv1connect.NewWorkspaceServiceClient(owner)
	sso := nokkuv1connect.NewSSOServiceClient(owner)
	issuer := fakeIssuer(t).URL
	enforce := func(on bool) error {
		_, err := workspaces.UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
			Settings: &nokkuv1.WorkspaceSettings{EnforceSso: new(on)},
		}))
		return err
	}
	put := func(id string, enabled bool) error {
		_, err := sso.PutSSOProvider(t.Context(), &nokkuv1.PutSSOProviderRequest{
			ProviderId: &id, Name: new("Keep"), Enabled: &enabled, IssuerUrl: new(issuer + "/" + id),
			ClientId: new("nokku"), ClientSecret: new("s3cret"),
		})
		return err
	}
	remove := func(id string) error {
		_, err := sso.DeleteSSOProvider(t.Context(), &nokkuv1.DeleteSSOProviderRequest{ProviderId: &id})
		return err
	}
	refused := func(err error, what string) {
		t.Helper()
		assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "%s: %v", what, err)
	}
	first, second := uniq("first"), uniq("second")

	refused(enforce(true), "enforcing with no provider")
	require.NoError(t, put(first, false))
	refused(enforce(true), "a disabled provider signs nobody in")
	require.NoError(t, put(first, true))
	require.NoError(t, enforce(true))

	refused(put(first, false), "disabling the last provider")
	refused(remove(first), "deleting the last provider")
	require.NoError(t, put(first, true), "saving the last provider as it is")

	require.NoError(t, put(second, true))
	require.NoError(t, put(first, false), "a second provider frees the first")
	require.NoError(t, remove(first))
	refused(remove(second), "deleting what became the last one")

	require.NoError(t, enforce(false))
	require.NoError(t, remove(second), "without the rule any provider can go")
}

// Enforced SSO ends sessions that came from elsewhere, but not the owner's.
func TestEnforceSSOEndsOtherSessions(t *testing.T) {
	cfg, _ := newTestAPI(t)
	srv := enterpriseServer(t)
	seedProvider(t, cfg)
	ws := testWorkspace.ID
	member := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	issue := func(u *db.User, kind actor.Kind, method iam.Method) string {
		p := iam.TokenParams{Kind: kind, Method: method}
		if kind == actor.KindCLI {
			p.SSHKey = testSSHKey
		}
		_, token, err := cfg.IAM.IssueSignIn(wsCtx(t), u, p)
		require.NoError(t, err)
		return token
	}
	owner := issue(seedOwner(t, cfg), actor.KindUser, iam.MethodPasskey)
	sessions := map[string]bool{
		issue(member, actor.KindUser, iam.MethodPasskey):   false,
		issue(member, actor.KindUser, iam.MethodMagicLink): false,
		issue(member, actor.KindCLI, iam.MethodPasskey):    false,
		issue(member, actor.KindUser, iam.MethodOIDC):      true,
		issue(member, actor.KindCLI, iam.MethodOIDC):       true,
		owner: true,
	}

	workspaces := nokkuv1connect.NewWorkspaceServiceClient(
		clientOn(srv, header("Authorization", "Bearer "+owner)),
	)
	var original *db.Workspace
	inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
		original, err = q.GetWorkspace(t.Context())
		return err
	})
	// Shared workspace, a mailed link would fail in every later test.
	t.Cleanup(func() { restoreWorkspace(context.WithoutCancel(t.Context()), t, cfg, original) })

	_, err := workspaces.UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
		Settings: &nokkuv1.WorkspaceSettings{EnforceSso: new(true)},
	}))
	require.NoError(t, err)

	for token, stays := range sessions {
		_, tok, err := cfg.IAM.AuthenticateToken(wsCtx(t), token, accessTokens...)
		if stays {
			require.NoError(t, err, "a %s session of kind %s was ended", tok.Method, tok.Kind)
			require.NotNil(t, tok.ExpiresAt, "a %s session of kind %s kept no end", tok.Method, tok.Kind)
			assert.WithinDuration(t, time.Now().Add(iam.SSOSessionTTL), *tok.ExpiresAt, time.Minute,
				"a session from before the rule outlives a new one")
		} else {
			assert.Error(t, err, "a session outlived the rule")
		}
	}
}

// An old owner session can rename the workspace, not change who may sign in.
func TestEnforcedSSONeedsARecentSignIn(t *testing.T) {
	cfg, _ := newTestAPI(t)
	srv := enterpriseServer(t)
	seedProvider(t, cfg)
	ws := testWorkspace.ID
	owner := seedOwner(t, cfg)
	var original *db.Workspace
	inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
		original, err = q.GetWorkspace(t.Context())
		return err
	})
	t.Cleanup(func() { restoreWorkspace(context.WithoutCancel(t.Context()), t, cfg, original) })

	client := func(age time.Duration) nokkuv1connect.WorkspaceServiceClient {
		return nokkuv1connect.NewWorkspaceServiceClient(clientOn(
			srv, signedIn(t, cfg, browserSession(t, cfg, owner, age)),
		))
	}

	_, err := client(time.Hour).UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
		Settings: &nokkuv1.WorkspaceSettings{EnforceSso: new(false)},
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "an old session changed enforced SSO: %v", err)

	_, err = client(
		time.Hour,
	).UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{Name: new("renamed")}))
	require.NoError(t, err, "a rename asked for a recent sign-in")

	_, err = client(0).UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
		Settings: &nokkuv1.WorkspaceSettings{EnforceSso: new(true)},
	}))
	require.NoError(t, err, "a recent sign-in was refused")
}

// Clearing a link signs the person out, and never reaches owner or caller.
func TestClearUserIdentities(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := testWorkspace.ID
	admin := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	member := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	link := func(u *db.User) {
		inWorkspace(t, cfg, ws, func(q *db.Queries) error {
			_, err := q.UpsertCredential(t.Context(), &db.UpsertCredentialParams{
				ID:       "oidc-" + u.ID,
				UserID:   u.ID,
				Type:     string(iam.MethodOIDC),
				Provider: "okta",
				Subject:  u.ID,
				Data:     []byte{},
			})
			return err
		})
	}
	links := func(u *db.User) (n int) {
		inWorkspace(t, cfg, ws, func(q *db.Queries) error {
			rows, err := q.ListUserCredentials(t.Context(), u.ID)
			n = len(rows)
			return err
		})
		return n
	}
	unlink := func(age time.Duration, u *db.User) error {
		_, err := nokkuv1connect.NewWorkspaceServiceClient(clientOn(
			srv, signedIn(t, cfg, browserSession(t, cfg, admin, age)),
		)).ClearUserIdentities(t.Context(), &nokkuv1.ClearUserIdentitiesRequest{UserId: new(u.ID)})
		return err
	}
	link(member)
	link(admin)
	session := sessionFor(t, cfg, member)

	assert.Equal(
		t,
		connect.CodeUnauthenticated,
		connect.CodeOf(unlink(time.Hour, member)),
		"an old session cleared a link",
	)
	assert.Equal(t, 1, links(member))

	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(unlink(0, admin)), "an admin cleared their own link")
	assert.Equal(
		t,
		connect.CodePermissionDenied,
		connect.CodeOf(unlink(0, seedOwner(t, cfg))),
		"an admin reached the owner",
	)

	require.NoError(t, unlink(0, member))
	assert.Zero(t, links(member), "the link stayed")
	_, _, err := cfg.IAM.AuthenticateToken(wsCtx(t), session, accessTokens...)
	assert.Error(t, err, "the session a wrong link gave lives on")
}
