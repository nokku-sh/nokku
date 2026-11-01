//go:build integration

package api_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// oldSignIn is past the ten minutes RequireRecentSignIn allows.
const oldSignIn = 11 * time.Minute

// Which routes that add a way in or move ownership refuse an old browser session, and which refuse nk.
func TestFreshSignInMatrix(t *testing.T) {
	// SCIM is a paid feature, the test workspace runs on an Enterprise license here.
	base, _ := enterprise(t)
	cfg, srv, _ := mailServer(t, base)
	ws := seedWorkspace(t, cfg)
	member := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	admin := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	owner := seedOwner(t, cfg)

	rpc := func(s login) *connect.Client {
		return connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), signedIn(t, cfg, s))
	}
	refusedRPC := func(err error) (string, bool) {
		code := connect.CodeOf(err)
		return rpcAnswer(
				err,
			), err != nil &&
				(code == connect.CodeUnauthenticated || code == connect.CodePermissionDenied)
	}

	providerID := uniq("link")
	issuer := fakeIssuer(t).URL + "/" + providerID
	provider := &nokkuv1.PutSSOProviderRequest{
		ProviderId: &providerID, Name: new("Link"), Enabled: new(true), IssuerUrl: &issuer,
		ClientId: new("nokku"), ClientSecret: new("s3cret"),
	}
	_, err := nokkuv1connect.NewSSOServiceClient(rpc(browserSession(t, cfg, owner, 0))).
		PutSSOProvider(t.Context(), provider)
	require.NoError(t, err)
	// The workspace is shared, the login page of later tests must not offer it.
	t.Cleanup(func() {
		ctx := actor.WithWorkspace(context.WithoutCancel(t.Context()), testWorkspace)
		require.NoError(t, cfg.IAM.DeleteSSOProvider(ctx, providerID))
	})
	sa, err := nokkuv1connect.NewServiceAccountServiceClient(rpc(browserSession(t, cfg, admin, 0))).
		CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{Name: new(uniq("sa"))})
	require.NoError(t, err)

	routes := []struct {
		name    string
		subject *db.User
		probe   func(s login) (string, bool)
	}{
		{"POST /passkey/register/begin", member, func(s login) (string, bool) {
			r := send(t, srv, http.MethodPost, "/passkey/register/begin", nil, withCookie(s.token))
			return r.String(), r.status == http.StatusUnauthorized
		}},
		{"GET /oidc/link", member, func(s login) (string, bool) {
			path := "/oidc/link?" + url.Values{"provider": {providerID}}.Encode()
			r := send(t, srv, http.MethodGet, path, nil, func(h http.Header) {
				withCookie(s.token)(h)
				h.Set("Sec-Fetch-Site", "same-origin")
			})
			if strings.HasPrefix(r.location, issuer+"/authorize?") {
				return r.String() + " to the provider", false
			}
			if r.location == "" {
				return r.String(), r.status == http.StatusUnauthorized || r.status == http.StatusForbidden
			}
			return r.String() + " to " + r.location, strings.Contains(r.location, "error=") || r.location == "/login"
		}},
		{"POST /auth/device/verify", member, func(s login) (string, bool) {
			grant := startDevice(t, srv)
			r := send(t, srv, http.MethodPost, "/auth/device/verify",
				url.Values{"user_code": {grant.UserCode}}, withCookie(s.token))
			return r.String(), r.status == http.StatusUnauthorized
		}},
		{"AccountService.RequestEmailChange", member, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewAccountServiceClient(rpc(s)).RequestEmailChange(t.Context(),
				&nokkuv1.RequestEmailChangeRequest{NewEmail: new(newMailAddress())})
			return refusedRPC(err)
		}},
		{"InvitationService.CreateInvitation", admin, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewInvitationServiceClient(rpc(s)).CreateInvitation(t.Context(),
				&nokkuv1.CreateInvitationRequest{Email: new(newMailAddress())})
			return refusedRPC(err)
		}},
		// The emergency kind, so no later test finds a replaced key still trusted on the shared CA.
		{"CertificateService.RolloverCertificateAuthority", admin, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewCertificateServiceClient(rpc(s)).RolloverCertificateAuthority(t.Context(),
				&nokkuv1.RolloverCertificateAuthorityRequest{RevokePrevious: new(true)})
			return refusedRPC(err)
		}},
		{"CertificateService.UpdateCertificateAuthority", admin, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewCertificateServiceClient(rpc(s)).UpdateCertificateAuthority(t.Context(),
				masked(&nokkuv1.UpdateCertificateAuthorityRequest{SourceAddress: new("")}))
			return refusedRPC(err)
		}},
		{"ServiceAccountService.UpdateServiceAccount limits", admin, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewServiceAccountServiceClient(rpc(s)).UpdateServiceAccount(t.Context(),
				masked(&nokkuv1.UpdateServiceAccountRequest{Id: sa.GetServiceAccount().Id, ForceCommand: new("")}))
			return refusedRPC(err)
		}},
		{"JoinTokenService.CreateJoinToken", admin, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewJoinTokenServiceClient(rpc(s)).CreateJoinToken(t.Context(),
				&nokkuv1.CreateJoinTokenRequest{})
			return refusedRPC(err)
		}},
		{"ServiceAccountService.CreateServiceAccountToken", admin, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewServiceAccountServiceClient(rpc(s)).CreateServiceAccountToken(t.Context(),
				&nokkuv1.CreateServiceAccountTokenRequest{
					ServiceAccountId: new(sa.GetServiceAccount().GetId()),
					ExpiresAt:        timestamppb.New(time.Now().Add(time.Hour)),
				})
			return refusedRPC(err)
		}},
		{"ServiceAccountService.AddServiceAccountFederation", admin, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewServiceAccountServiceClient(rpc(s)).AddServiceAccountFederation(t.Context(),
				&nokkuv1.AddServiceAccountFederationRequest{
					ServiceAccountId: new(sa.GetServiceAccount().GetId()),
					Issuer:           new("https://ci.example.test"),
					Claims:           map[string]string{"sub": "job"},
				})
			return refusedRPC(err)
		}},
		// No rule has this id. A call that gets past the fresh check answers not_found.
		{"ServiceAccountService.RemoveServiceAccountFederation", admin, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewServiceAccountServiceClient(rpc(s)).RemoveServiceAccountFederation(t.Context(),
				&nokkuv1.RemoveServiceAccountFederationRequest{
					ServiceAccountId: new(sa.GetServiceAccount().GetId()),
					Id:               new(uuid.NewV7().String()),
				})
			return refusedRPC(err)
		}},
		{"SCIMService.CreateSCIMToken", owner, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewSCIMServiceClient(rpc(s)).CreateSCIMToken(t.Context(),
				&nokkuv1.CreateSCIMTokenRequest{Label: new("idp")})
			return refusedRPC(err)
		}},
		{"SSOService.PutSSOProvider", owner, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewSSOServiceClient(rpc(s)).PutSSOProvider(t.Context(), provider)
			return refusedRPC(err)
		}},
		// The shared owner stays, a new owner nobody has makes the handler answer not_found once it runs.
		{"WorkspaceService.TransferOwnership", owner, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewWorkspaceServiceClient(rpc(s)).TransferOwnership(t.Context(),
				&nokkuv1.TransferOwnershipRequest{NewOwnerId: new(uuid.NewV7().String())})
			return refusedRPC(err)
		}},
		{"WorkspaceService.DeleteWorkspace", owner, func(s login) (string, bool) {
			_, err := nokkuv1connect.NewWorkspaceServiceClient(rpc(s)).DeleteWorkspace(t.Context(),
				&nokkuv1.DeleteWorkspaceRequest{})
			return refusedRPC(err)
		}},
	}

	terminals := map[string]login{}
	terminal := func(u *db.User) login {
		if s, ok := terminals[u.ID]; ok {
			return s
		}
		terminals[u.ID] = deviceLogin(t, cfg, srv, u)
		return terminals[u.ID]
	}
	lines := []string{
		"# route | session | session check | answer | session after",
		"# browser sessions are the nokku_session cookie. cli is a device flow session of nk: as the cookie on",
		"# plain HTTP routes, as Authorization: DPoP with a proof on RPCs. old is signed in 11m ago.",
	}
	for _, r := range routes {
		// It would delete the workspace every test shares, TestHostedDeleteWorkspace has its own.
		if hosted && r.name == "WorkspaceService.DeleteWorkspace" {
			continue
		}
		for _, c := range []struct {
			name string
			s    login
		}{
			{"browser fresh", browserSession(t, cfg, r.subject, 0)},
			{"browser old", browserSession(t, cfg, r.subject, oldSignIn)},
			{"cli", terminal(r.subject)},
		} {
			answer, refused := r.probe(c.s)
			verdict := "accepted"
			if refused {
				verdict = "refused"
			}
			lines = append(lines, strings.Join(
				[]string{r.name, c.name, verdict, answer, sessionAfter(t, cfg, c.s.token)}, " | ",
			))
		}
	}
	assertGolden(t, hostedGolden("fresh_signin.golden"), lines)
}

// The web app reads fresh_for to ask for a new sign-in before a form opens, so it counts like the check does.
func TestSessionsSayHowLongTheyStayFresh(t *testing.T) {
	base, _ := enterprise(t)
	cfg, srv, _ := mailServer(t, base)
	seedWorkspace(t, cfg)
	owner := seedOwner(t, cfg)
	freshFor := func(s login) time.Duration {
		t.Helper()
		client := nokkuv1connect.NewAccountServiceClient(
			connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), signedIn(t, cfg, s)),
		)
		res, err := client.ListAccountSessions(t.Context(), &nokkuv1.ListAccountSessionsRequest{})
		require.NoError(t, err)
		for _, sess := range res.GetSessions() {
			if sess.GetCurrent() {
				return sess.GetFreshFor().AsDuration()
			}
		}
		t.Fatal("the list has no current session")
		return 0
	}

	fresh := freshFor(browserSession(t, cfg, owner, 0))
	assert.Greater(t, fresh, 9*time.Minute)
	assert.LessOrEqual(t, fresh, 10*time.Minute)
	assert.Zero(t, freshFor(browserSession(t, cfg, owner, oldSignIn)))
	assert.Zero(t, freshFor(deviceLogin(t, cfg, srv, owner)), "nk never makes a fresh call")
}
