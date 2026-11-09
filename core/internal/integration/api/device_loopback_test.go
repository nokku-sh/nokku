//go:build integration

package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// A loopback grant answers only to the code its approval hands the browser. So
// a link someone else sends signs in nobody, even once it is approved.
func TestDeviceLoopbackNeedsTheBrowsersCode(t *testing.T) {
	cfg, srv := newTestAPI(t)
	member := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	approver := browserSession(t, cfg, member, 0)

	begun := send(t, srv, http.MethodPost, "/auth/device", url.Values{"loopback_port": {"40123"}}, nil)
	require.Equal(t, http.StatusOK, begun.status, begun.String())
	deviceCode, _ := begun.body["device_code"].(string)
	userCode, _ := begun.body["user_code"].(string)
	assert.Contains(t, begun.body["verification_uri_complete"], "user_code="+userCode,
		"a loopback grant is safe to open from its link")

	info := send(t, srv, http.MethodGet, "/auth/device/info?user_code="+userCode, nil, withCookie(approver.token))
	assert.Equal(t, true, info.body["loopback"], info.String())

	approved := send(t, srv, http.MethodPost, "/auth/device/verify",
		url.Values{"user_code": {userCode}}, withCookie(approver.token))
	require.Equal(t, http.StatusOK, approved.status, approved.String())
	redirect, _ := approved.body["redirect"].(string)
	require.True(t, strings.HasPrefix(redirect, "http://127.0.0.1:40123/callback?code=nk_loopback_"), redirect)
	answer, err := url.Parse(redirect)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	poll := func(code string) reply {
		t.Helper()
		const path = "/auth/device/token"
		form := url.Values{"device_code": {deviceCode}, "ssh_public_key": {sshKeyOf(t, key)}, "code": {code}}
		return send(t, srv, http.MethodPost, path, form, func(h http.Header) {
			h.Set("DPoP", dpopProof(t, cfg, key, path, ""))
		})
	}
	assert.Equal(t, "authorization_pending", poll("").body["error"], "the device code alone signed in")
	assert.Equal(t, "invalid_grant", poll("nk_loopback_guess").body["error"], "a guessed code signed in")

	signedIn := poll(answer.Query().Get("code"))
	require.Equal(t, http.StatusOK, signedIn.status, signedIn.String())
	assert.NotEmpty(t, signedIn.body["access_token"])
}

// A denial goes to nk the same way, so it stops waiting.
func TestDeviceLoopbackDenialReachesNk(t *testing.T) {
	cfg, srv := newTestAPI(t)
	member := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	approver := browserSession(t, cfg, member, 0)

	begun := send(t, srv, http.MethodPost, "/auth/device", url.Values{"loopback_port": {"40124"}}, nil)
	require.Equal(t, http.StatusOK, begun.status, begun.String())
	userCode, _ := begun.body["user_code"].(string)
	denied := send(t, srv, http.MethodPost, "/auth/device/deny",
		url.Values{"user_code": {userCode}}, withCookie(approver.token))
	require.Equal(t, http.StatusOK, denied.status, denied.String())
	assert.Equal(t, "http://127.0.0.1:40124/callback?error=access_denied", denied.body["redirect"])
}

// A headless code is typed on the approving device. No link approves it.
func TestDeviceHeadlessHasNoLink(t *testing.T) {
	cfg, srv := newTestAPI(t)
	member := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	approver := browserSession(t, cfg, member, 0)

	grant := startDevice(t, srv)
	begun := send(t, srv, http.MethodPost, "/auth/device", nil, nil)
	assert.NotContains(t, begun.body, "verification_uri_complete", "a headless grant offered a link to approve")

	info := send(t, srv, http.MethodGet, "/auth/device/info?user_code="+grant.UserCode, nil, withCookie(approver.token))
	assert.Equal(t, false, info.body["loopback"], info.String())
	approved := send(t, srv, http.MethodPost, "/auth/device/verify",
		url.Values{"user_code": {grant.UserCode}}, withCookie(approver.token))
	require.Equal(t, http.StatusOK, approved.status, approved.String())
	assert.NotContains(t, approved.body, "redirect", "a headless approval has nowhere to send the browser")
}

func TestDeviceRefusesABadLoopbackPort(t *testing.T) {
	_, srv := newTestAPI(t)
	for _, port := range []string{"80", "0", "70000", "x", "-1"} {
		r := send(t, srv, http.MethodPost, "/auth/device", url.Values{"loopback_port": {port}}, nil)
		assert.Equal(t, http.StatusBadRequest, r.status, "port %q: %s", port, r.String())
	}
}
