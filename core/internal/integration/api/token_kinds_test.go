//go:build integration

package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

// Each secret handed out: its format, that it works, how a tampered copy fails.
func TestTokenKinds(t *testing.T) {
	// SCIM is paid and an invite needs a seat, the Enterprise license has both.
	base, _ := enterprise(t)
	cfg, srv, box := mailServer(t, base)
	ctx := t.Context()
	ws := testWorkspace.ID
	owner := browserSession(t, cfg, seedOwner(t, cfg), 0)
	as := func(s login) *connect.Client { return clientOn(srv, signedIn(t, cfg, s)) }
	bearer := func(token string) *connect.Client {
		return clientOn(srv, header("Authorization", "Bearer "+token))
	}
	whoami := func(client *connect.Client) string {
		res, err := nokkuv1connect.NewTargetServiceClient(client).
			GetSubjectAccess(ctx, &nokkuv1.GetSubjectAccessRequest{})
		if err != nil {
			return "GetSubjectAccess " + rpcAnswer(err)
		}
		if res.GetServiceAccount() != nil {
			return "GetSubjectAccess as service account"
		}
		return "GetSubjectAccess as user"
	}
	scim := func(token string) string {
		const path = "/scim/v2/ServiceProviderConfig"
		r := send(t, srv, http.MethodGet, path, nil, func(h http.Header) { h.Set("Authorization", "Bearer "+token) })
		return "GET " + path + " " + r.String()
	}
	auth := nokkuv1connect.NewAuthServiceClient(clientOn(srv))

	lines := []string{
		"# kind | fact | value",
		"# tampered is a copy with one character in the middle of its random part changed.",
		"# <base> is the workspace URL.",
	}
	fact := func(kind, what, value string) {
		lines = append(lines, kind+" | "+what+" | "+value)
	}

	const magicLink = "magic sign-in link"
	reader := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	_, err := auth.RequestMagicLink(ctx, &nokkuv1.RequestMagicLinkRequest{Email: &reader.Email})
	require.NoError(t, err)
	link := box.next(t, reader.Email)
	fact(magicLink, "shape", shape(link))
	token := tokenOf(t, link)
	_, err = auth.ConsumeMagicLink(ctx, &nokkuv1.ConsumeMagicLinkRequest{Token: new(tamper(token))})
	fact(magicLink, "tampered", "ConsumeMagicLink "+rpcAnswer(err))
	signInCtx, signIn := connect.NewClientContext(ctx)
	signedInAs, err := auth.ConsumeMagicLink(signInCtx, &nokkuv1.ConsumeMagicLinkRequest{Token: &token})
	require.NoError(t, err)
	assert.Equal(t, reader.ID, signedInAs.GetUser().GetId())
	fact(magicLink, "verifies", "ConsumeMagicLink "+rpcAnswer(err))

	cookies := map[string]*http.Cookie{}
	for _, line := range signIn.ResponseHeader().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)
		cookies[c.Name] = c
	}
	const browser = "browser session cookie"
	session := cookies[sessionCookie]
	require.NotNil(t, session, "the sign-in set no session cookie")
	fact(browser, "name", session.Name)
	fact(browser, "shape", shape(session.Value))
	fact(browser, "attributes", cookieAttributes(session))
	fact(browser, "tampered", whoami(as(login{token: tamper(session.Value)})))
	fact(browser, "verifies", whoami(as(login{token: session.Value})))

	const device = "remembered device cookie"
	remembered := cookies[cookieNamed("nokku_device_")+reader.ID]
	require.NotNil(t, remembered, "a new browser gets the device cookie")
	fact(device, "name", cookieNamed("nokku_device_")+"<user id>")
	fact(device, "shape", shape(remembered.Value))
	fact(device, "attributes", cookieAttributes(remembered))
	fact(device, "as a session", whoami(as(login{token: remembered.Value})))

	const deviceCode, userCode, cli = "device code", "user code", "cli session"
	grant := startDevice(t, srv)
	fact(deviceCode, "shape", shape(grant.DeviceCode))
	fact(userCode, "shape", shape(grant.UserCode))
	approver := withCookie(browserSession(t, cfg, reader, 0).token)
	info := func(code string) string {
		return "GET /auth/device/info " +
			send(t, srv, http.MethodGet, "/auth/device/info?user_code="+url.QueryEscape(code), nil, approver).String()
	}
	approve := func(code string) string {
		return "POST /auth/device/verify " +
			send(t, srv, http.MethodPost, "/auth/device/verify", url.Values{"user_code": {code}}, approver).String()
	}
	fact(userCode, "tampered", info(tamper(grant.UserCode)))
	fact(userCode, "tampered", approve(tamper(grant.UserCode)))
	fact(userCode, "verifies", info(grant.UserCode))
	fact(userCode, "verifies", approve(grant.UserCode))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tampered := pollDevice(t, cfg, srv, tamper(grant.DeviceCode), key)
	fact(deviceCode, "tampered", "POST /auth/device/token "+tampered.String())
	polled := pollDevice(t, cfg, srv, grant.DeviceCode, key)
	require.Equal(t, http.StatusOK, polled.status, polled.String())
	fact(deviceCode, "verifies",
		fmt.Sprintf("POST /auth/device/token %s token_type %v", polled, polled.body["token_type"]))
	terminal, _ := polled.body["access_token"].(string)
	fact(cli, "shape", shape(terminal))
	fact(cli, "tampered", whoami(as(login{token: tamper(terminal), key: key})))
	fact(cli, "without its proof", whoami(clientOn(srv, header("Authorization", "DPoP "+terminal))))
	fact(cli, "verifies", whoami(as(login{token: terminal, key: key})))

	const enrollToken, daemon = "enroll token", "daemon session"
	created, err := nokkuv1connect.NewJoinTokenServiceClient(as(owner)).CreateJoinToken(ctx,
		&nokkuv1.CreateJoinTokenRequest{
			AutoApprove: new(true),
		})
	require.NoError(t, err)
	host, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enroll := func(token string) (*nokkuv1.EnrollDaemonResponse, error) {
		proof := header("DPoP", dpopProof(t, cfg, host, nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure, ""))
		return nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, proof)).
			EnrollDaemon(ctx, &nokkuv1.EnrollDaemonRequest{Token: &token})
	}
	fact(enrollToken, "shape", shape(created.GetSecret()))
	_, err = enroll(tamper(created.GetSecret()))
	fact(enrollToken, "tampered", "EnrollDaemon "+rpcAnswer(err))
	enrolled, err := enroll(created.GetSecret())
	require.NoError(t, err)
	fact(enrollToken, "verifies", "EnrollDaemon "+rpcAnswer(err))

	sync := func(client *connect.Client) string {
		_, err := nokkuv1connect.NewDaemonControlServiceClient(client).SyncDaemon(ctx, &nokkuv1.SyncDaemonRequest{})
		return "SyncDaemon " + rpcAnswer(err)
	}
	signed := func(token string) *connect.Client {
		return clientOn(srv,
			daemonAuth(t, cfg, host, token, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure))
	}
	hostToken := enrolled.GetAccessToken()
	fact(daemon, "shape", shape(hostToken))
	fact(daemon, "tampered", sync(signed(tamper(hostToken))))
	fact(daemon, "without its proof", sync(clientOn(srv, header("Authorization", "DPoP "+hostToken))))
	fact(daemon, "verifies", sync(signed(hostToken)))

	const serviceKey = "service account key"
	accounts := nokkuv1connect.NewServiceAccountServiceClient(as(owner))
	account, err := accounts.CreateServiceAccount(ctx, &nokkuv1.CreateServiceAccountRequest{Name: new(uniq("sa"))})
	require.NoError(t, err)
	issued, err := accounts.CreateServiceAccountToken(ctx, &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: new(account.GetServiceAccount().GetId()),
		ExpiresAt:        timestamppb.New(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)
	secret := issued.GetSecret()
	fact(serviceKey, "shape", shape(secret))
	fact(serviceKey, "tampered", whoami(bearer(tamper(secret))))
	fact(serviceKey, "on the SCIM API", scim(secret))
	fact(serviceKey, "verifies", whoami(bearer(secret)))

	const scimKey = "SCIM key"
	provisioning, err := nokkuv1connect.NewSCIMServiceClient(as(owner)).
		CreateSCIMToken(ctx, &nokkuv1.CreateSCIMTokenRequest{Label: new("idp")})
	require.NoError(t, err)
	fact(scimKey, "shape", shape(provisioning.GetToken()))
	fact(scimKey, "tampered", scim(tamper(provisioning.GetToken())))
	fact(scimKey, "on the RPC API", whoami(bearer(provisioning.GetToken())))
	fact(scimKey, "verifies", scim(provisioning.GetToken()))

	const invite = "invite link"
	newcomer := newMailAddress()
	_, err = nokkuv1connect.NewInvitationServiceClient(as(owner)).CreateInvitation(ctx,
		&nokkuv1.CreateInvitationRequest{Email: &newcomer})
	require.NoError(t, err)
	link = box.next(t, newcomer)
	fact(invite, "shape", shape(link))
	token = tokenOf(t, link)
	invitations := nokkuv1connect.NewInvitationServiceClient(clientOn(srv))
	_, err = invitations.GetInvitation(ctx, &nokkuv1.GetInvitationRequest{Token: new(tamper(token))})
	fact(invite, "tampered", "GetInvitation "+rpcAnswer(err))
	_, err = invitations.GetInvitation(ctx, &nokkuv1.GetInvitationRequest{Token: &token})
	fact(invite, "verifies", "GetInvitation "+rpcAnswer(err))
	_, err = invitations.AcceptInvitation(ctx,
		&nokkuv1.AcceptInvitationRequest{Token: new(tamper(token)), Name: new("Newcomer")})
	fact(invite, "tampered", "AcceptInvitation "+rpcAnswer(err))
	joined, err := invitations.AcceptInvitation(ctx,
		&nokkuv1.AcceptInvitationRequest{Token: &token, Name: new("Newcomer")})
	require.NoError(t, err)
	assert.Equal(t, newcomer, joined.GetUser().GetEmail())
	fact(invite, "verifies", "AcceptInvitation "+rpcAnswer(err))

	// The API's mails go nowhere here, so these tokens come from iam.
	const confirmLink, cancelLink = "email change confirm token", "email change cancel token"
	mover := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	confirm, cancel, err := cfg.IAM.RequestEmailChange(wsCtx(t), mover, newMailAddress())
	require.NoError(t, err)
	fact(confirmLink, "shape", shape(confirm))
	_, err = auth.ConfirmEmailChange(ctx, &nokkuv1.ConfirmEmailChangeRequest{Token: new(tamper(confirm))})
	fact(confirmLink, "tampered", "ConfirmEmailChange "+rpcAnswer(err))
	_, err = auth.ConfirmEmailChange(ctx, &nokkuv1.ConfirmEmailChangeRequest{Token: &confirm})
	fact(confirmLink, "verifies", "ConfirmEmailChange "+rpcAnswer(err))
	fact(cancelLink, "shape", shape(cancel))
	_, err = auth.CancelEmailChange(ctx, &nokkuv1.CancelEmailChangeRequest{Token: new(tamper(cancel))})
	fact(cancelLink, "tampered", "CancelEmailChange "+rpcAnswer(err))
	_, err = auth.CancelEmailChange(ctx, &nokkuv1.CancelEmailChangeRequest{Token: &cancel})
	fact(cancelLink, "verifies", "CancelEmailChange "+rpcAnswer(err))

	assertGolden(t, hostedGolden("token_kinds.golden"), lines)
}

func tokenOf(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	require.NoError(t, err)
	token := u.Query().Get("token")
	require.NotEmpty(t, token, "the link carries no token")
	return token
}

// cookieAttributes gives how long the cookie lives, not its expiry date.
func cookieAttributes(c *http.Cookie) string {
	sameSite := map[http.SameSite]string{
		http.SameSiteDefaultMode: "default",
		http.SameSiteLaxMode:     "Lax",
		http.SameSiteStrictMode:  "Strict",
		http.SameSiteNoneMode:    "None",
	}[c.SameSite]
	parts := []string{"Path=" + c.Path, "SameSite=" + sameSite}
	if c.HttpOnly {
		parts = append(parts, "HttpOnly")
	}
	if c.Secure {
		parts = append(parts, "Secure")
	}
	parts = append(parts, "lives "+time.Until(c.Expires).Round(time.Hour).String())
	return strings.Join(parts, " ")
}
