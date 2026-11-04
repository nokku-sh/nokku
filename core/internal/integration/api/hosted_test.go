//go:build integration

package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/tenant"
)

const (
	hostedBase = "nokku.test"
	hostedSlug = "acme"
)

// hosted runs like the service: NOKKU_SAAS, a KMS, a workspace found by host.
var hosted = os.Getenv("NOKKU_TEST_HOSTED") != ""

// cookieNamed is what a browser gets, https cookies carry __Host-.
func cookieNamed(name string) string {
	if hosted {
		return "__Host-" + name
	}
	return name
}

// newMailAddress passes the hosted check, only localhost resolves without DNS.
func newMailAddress() string {
	return uuid.New().String() + "@localhost"
}

// hostedGolden is for a file with facts that differ on the hosted service.
func hostedGolden(name string) string {
	if hosted {
		return "hosted_" + name
	}
	return name
}

func selfHostedOnly(t *testing.T, why string) {
	t.Helper()
	if hosted {
		t.Skip(why)
	}
}

// withoutAPlan ends a hosted trial until restore, self-hosted has no plan.
func withoutAPlan(t *testing.T, cfg *config.Config) (restore func()) {
	t.Helper()
	if !hosted {
		return func() {}
	}
	sub, err := cfg.Conn.Sys().GetSubscription(t.Context(), testWorkspace.ID)
	require.NoError(t, err)
	put := func(ctx context.Context, source string, end *time.Time) {
		require.NoError(t, cfg.Conn.Sys().UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
			WorkspaceID:      sub.WorkspaceID,
			Source:           source,
			Plan:             sub.Plan,
			Status:           sub.Status,
			CurrentPeriodEnd: end,
		}))
	}
	put(t.Context(), entitlement.SourceTrial, new(time.Now().Add(-time.Hour)))
	return func() { put(context.WithoutCancel(t.Context()), sub.Source, sub.CurrentPeriodEnd) }
}

// hostedWorkspace is the shared workspace, on a plan with no limits.
func hostedWorkspace(ctx context.Context, cfg *config.Config) (actor.Workspace, error) {
	ws, err := tenant.Create(ctx, cfg.Conn, cfg.Keyset, hostedSlug, "test")
	if err != nil {
		return actor.Workspace{}, err
	}
	err = cfg.Conn.Sys().UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
		WorkspaceID:      ws.ID,
		Source:           entitlement.SourceStripe,
		Plan:             entitlement.PlanEnterprise,
		Status:           "active",
		CurrentPeriodEnd: new(time.Now().AddDate(1, 0, 0)),
	})
	if err != nil {
		return actor.Workspace{}, err
	}
	return cfg.Tenant.FromHost(ctx, hostedSlug+"."+hostedBase)
}

// serving puts a loopback request on the workspace's https host, if hosted.
func serving(next http.Handler) http.Handler {
	if !hosted {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = hostedSlug + "." + hostedBase
		r.Header.Set("X-Forwarded-Proto", "https")
		next.ServeHTTP(w, r)
	})
}

func hostedOnly(t *testing.T) {
	t.Helper()
	if !hosted {
		t.Skip("set NOKKU_TEST_HOSTED")
	}
}

// onHost is the suite's server as a request for host reaches it.
func onHost(t *testing.T, host string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = host
		r.Header.Set("X-Forwarded-Proto", "https")
		testHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newHostedWorkspace(t *testing.T, cfg *config.Config) actor.Workspace {
	t.Helper()
	slug := "t" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	_, err := tenant.Create(t.Context(), cfg.Conn, cfg.Keyset, slug, "other")
	require.NoError(t, err)
	ws, err := cfg.Tenant.FromHost(t.Context(), slug+"."+hostedBase)
	require.NoError(t, err)
	return ws
}

func workspacesOn(srv *httptest.Server, auth ...connect.ClientInterceptor) nokkuv1connect.WorkspaceServiceClient {
	return nokkuv1connect.NewWorkspaceServiceClient(
		clientOn(srv, auth...),
	)
}

func instanceInfoStatus(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	res, err := srv.Client().Post(
		srv.URL+nokkuv1connect.UtilServiceGetInstanceInfoProcedure, "application/json", strings.NewReader("{}"),
	)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode
}

// A host nobody cached costs a database lookup before any sign-in, so one
// client gets a bounded number of those. A cached host never counts.
func TestHostedUnknownHostsAreLimited(t *testing.T) {
	hostedOnly(t)
	cfg, _ := newTestAPI(t)
	// Its own handler, so the misses here spend no other test's budget.
	handler := api.New(cfg).Handler(t.Context())
	get := func(host string) int {
		req := httptest.NewRequest(http.MethodGet, "/_app/version.json", nil)
		req.Host = host
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	limited := 0
	for i := range 1000 {
		if get(fmt.Sprintf("nobody%d.%s", i, hostedBase)) == http.StatusTooManyRequests {
			limited = i
			break
		}
	}
	require.NotZero(t, limited, "a thousand unknown hosts all reached the database")

	_, err := cfg.Tenant.FromHost(t.Context(), hostedSlug+"."+hostedBase)
	require.NoError(t, err)
	assert.NotEqual(t, http.StatusTooManyRequests, get(hostedSlug+"."+hostedBase), "a cached host was counted")
	assert.NotEqual(t, http.StatusTooManyRequests, get(hostedBase), "the root host was counted")
}

// Only the root host and real workspaces answer, a health check needs none.
func TestHostedHostPicksTheWorkspace(t *testing.T) {
	hostedOnly(t)
	for host, want := range map[string]int{
		hostedBase:                            http.StatusOK,
		hostedSlug + "." + hostedBase:         http.StatusOK,
		"ACME." + strings.ToUpper(hostedBase): http.StatusOK,
		"nobody." + hostedBase:                http.StatusNotFound,
		"a." + hostedSlug + "." + hostedBase:  http.StatusNotFound,
		"api." + hostedBase:                   http.StatusNotFound,
		hostedBase + ".evil.example":          http.StatusNotFound,
	} {
		srv := onHost(t, host)
		assert.Equal(t, want, instanceInfoStatus(t, srv), host)

		res, err := srv.Client().Get(srv.URL + "/healthz")
		require.NoError(t, err)
		_ = res.Body.Close()
		assert.Equal(t, http.StatusOK, res.StatusCode, host)
	}

	info := func(host string) *nokkuv1.GetInstanceInfoResponse {
		srv := onHost(t, host)
		res, err := nokkuv1connect.NewUtilServiceClient(
			clientOn(srv),
		).GetInstanceInfo(t.Context(), &nokkuv1.GetInstanceInfoRequest{})
		require.NoError(t, err)
		return res
	}
	assert.True(t, info(hostedBase).GetSignup(), "the root host is where people sign up")
	assert.False(t, info(hostedSlug+"."+hostedBase).GetSignup(), "a workspace host signs nobody up")
}

// Row security hides a token from every other host, in a header and a cookie.
func TestHostedSessionWorksOnItsOwnHostOnly(t *testing.T) {
	hostedOnly(t)
	cfg, own := newTestAPI(t)
	foreign := onHost(t, newHostedWorkspace(t, cfg).Slug+"."+hostedBase)
	token := seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)

	for name, auth := range map[string]connect.ClientInterceptor{
		"header": header("Authorization", "Bearer "+token),
		"cookie": header("Cookie", sessionCookie+"="+token),
	} {
		_, err := workspacesOn(own, auth).GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
		require.NoError(t, err, name)
		_, err = workspacesOn(foreign, auth).GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
		assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "%s: %v", name, err)
	}
}

// A signup gets its own host, the first sign-in keeps it from the purge.
func TestHostedSignup(t *testing.T) {
	hostedOnly(t)
	cfg, shared := newTestAPI(t)
	root := workspacesOn(onHost(t, hostedBase))
	slug, addr := "s"+strings.ReplaceAll(uuid.New().String(), "-", "")[:12], newMailAddress()
	signup := func(c nokkuv1connect.WorkspaceServiceClient, slug, addr string) (*nokkuv1.CreateWorkspaceResponse, error) {
		return c.CreateWorkspace(t.Context(), &nokkuv1.CreateWorkspaceRequest{
			Slug: &slug, Name: new("Signup"), OwnerEmail: &addr,
		})
	}

	res, err := signup(root, slug, addr)
	require.NoError(t, err)
	assert.Equal(t, "https://"+slug+"."+hostedBase, res.GetUrl())

	_, err = signup(root, slug, newMailAddress())
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err), "got %v", err)
	_, err = signup(root, "other"+slug, addr)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "a second mail right away: %v", err)
	_, err = signup(root, "api", newMailAddress())
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "a reserved name: %v", err)
	_, err = signup(workspacesOn(shared), "other"+slug, newMailAddress())
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "signup on a workspace host: %v", err)

	host := slug + "." + hostedBase
	ws, err := cfg.Tenant.FromHost(t.Context(), host)
	require.NoError(t, err)
	row, err := cfg.Conn.Sys().GetWorkspaceBySlug(t.Context(), slug)
	require.NoError(t, err)
	assert.Nil(t, row.ClaimedAt, "nobody signed in yet")

	ctx := actor.WithWorkspace(t.Context(), ws)
	var owner *db.User
	require.NoError(t, cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		owner, err = q.GetOwner(ctx)
		return err
	}))
	link, err := cfg.IAM.IssueBootstrapLink(ctx, owner)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(link, "https://"+host+"/"), "the link goes to the new host: %s", link)
	_, token, _ := strings.Cut(link, "token=")

	srv := onHost(t, host)
	_, err = nokkuv1connect.NewAuthServiceClient(clientOn(srv)).
		ConsumeMagicLink(t.Context(), &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	require.NoError(t, err)
	row, err = cfg.Conn.Sys().GetWorkspaceBySlug(t.Context(), slug)
	require.NoError(t, err)
	assert.NotNil(t, row.ClaimedAt, "the first sign-in claims the workspace")
}

// A deleted workspace leaves its host at once, the host cache must not keep it.
func TestHostedDeleteWorkspace(t *testing.T) {
	hostedOnly(t)
	cfg, shared := newTestAPI(t)
	ws := newHostedWorkspace(t, cfg)
	srv := onHost(t, ws.Slug+"."+hostedBase)
	owner := seedUser(t, cfg, ws.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	signIn := func() (*db.AccessToken, string) {
		tok, token, err := cfg.IAM.IssueSignIn(
			actor.WithWorkspace(t.Context(), ws),
			owner,
			iam.TokenParams{Kind: actor.KindUser, Method: iam.MethodPasskey},
		)
		require.NoError(t, err)
		return tok, token
	}
	remove := func(token string) error {
		_, err := workspacesOn(srv, header("Authorization", "Bearer "+token)).
			DeleteWorkspace(t.Context(), &nokkuv1.DeleteWorkspaceRequest{})
		return err
	}

	old, token := signIn()
	ageSession(t, old.ID, oldSignIn)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(remove(token)), "an old sign-in deletes nothing")
	require.Equal(t, http.StatusOK, instanceInfoStatus(t, srv))

	_, token = signIn()
	require.NoError(t, remove(token))

	assert.Equal(t, http.StatusNotFound, instanceInfoStatus(t, srv))
	assert.Equal(t, http.StatusOK, instanceInfoStatus(t, shared), "the other workspaces stay")
}
