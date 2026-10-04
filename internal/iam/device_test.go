package iam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

const terminalAgent = "nk/1.0.0 (linux/amd64)"

// devicePost sends one form request of the device flow, as u when given.
func devicePost(handler http.HandlerFunc, path, remote string, form url.Values, u *db.User) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", terminalAgent)
	r.RemoteAddr = remote
	if u != nil {
		r = r.WithContext(actor.ContextWithPrincipal(r.Context(), actor.Principal{ID: u.ID, Kind: actor.KindUser}))
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

// terminalSignIn runs a whole device login for u from the machine that holds
// key, and returns how long the session lasts.
func terminalSignIn(t *testing.T, e *testEnv, u *db.User, key *ecdsa.PrivateKey) time.Duration {
	t.Helper()
	var grant struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	begun := devicePost(e.svc.Device.Begin, "/auth/device", "198.51.100.9:6000", nil, nil)
	require.Equal(t, http.StatusOK, begun.Code)
	require.NoError(t, json.Unmarshal(begun.Body.Bytes(), &grant))
	approved := devicePost(
		e.svc.Device.Verify, "/auth/device/verify", "192.0.2.1:1", url.Values{"user_code": {grant.UserCode}}, u,
	)
	require.Equal(t, http.StatusOK, approved.Code)

	const pollPath = "/auth/device/token"
	poll := httptest.NewRequest(
		http.MethodPost,
		pollPath,
		strings.NewReader(url.Values{"device_code": {grant.DeviceCode}}.Encode()),
	)
	poll.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	poll.Header.Set("User-Agent", terminalAgent)
	poll.Header.Set("DPoP", signProof(t, key, e.svc.baseURL+pollPath, "", e.svc.DPoP.CurrentNonce(), time.Now()))
	poll.RemoteAddr = "198.51.100.9:6000"
	polled := httptest.NewRecorder()
	e.svc.Device.Poll(polled, poll)
	require.Equal(t, http.StatusOK, polled.Code, polled.Body.String())

	var token struct {
		ExpiresIn int `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(polled.Body.Bytes(), &token))
	return time.Duration(token.ExpiresIn) * time.Second
}

// The approver sees who asked for the code before anything is approved. That
// is what gives a phished device code away.
func TestDeviceFlowShowsRequester(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "user@"+testDomain(), true)
	info := func(userCode string) (int, map[string]string) {
		t.Helper()
		w := httptest.NewRecorder()
		e.svc.Device.Info(w, httptest.NewRequest(http.MethodGet, "/auth/device/info?user_code="+userCode, nil))
		var body map[string]string
		if w.Code == http.StatusOK {
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		}
		return w.Code, body
	}

	var grant struct {
		UserCode string `json:"user_code"`
	}
	begun := devicePost(e.svc.Device.Begin, "/auth/device", "203.0.113.7:5000", nil, nil)
	require.Equal(t, http.StatusOK, begun.Code)
	require.NoError(t, json.Unmarshal(begun.Body.Bytes(), &grant))

	status, requester := info(strings.ToLower(grant.UserCode))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, map[string]string{"ip": "203.0.113.7", "user_agent": terminalAgent}, requester)
	status, _ = info("BCDF-GHJK")
	assert.Equal(t, http.StatusNotFound, status, "an unknown code")

	approved := devicePost(
		e.svc.Device.Verify, "/auth/device/verify", "192.0.2.1:1", url.Values{"user_code": {grant.UserCode}}, u,
	)
	require.Equal(t, http.StatusOK, approved.Code)
	status, _ = info(grant.UserCode)
	assert.Equal(t, http.StatusNotFound, status, "a decided code")
}

// A terminal is mailed once, when its key is new to the account. Signing in
// again from the same machine is quiet, so the mail keeps meaning something.
func TestTerminalSignInMailsOnlyNewKeys(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "user@"+testDomain(), true)
	mailed := make(chan string, 4)
	e.svc.OnNewDeviceLogin = func(_ context.Context, to *db.User, sess *db.Session, label, ip string) {
		mailed <- to.ID + " " + label + " " + ip + " " + sess.Kind
	}
	wantMail := func(want bool, msg string) {
		t.Helper()
		select {
		case got := <-mailed:
			require.True(t, want, "%s, but got a mail", msg)
			assert.Equal(t, u.ID+" "+terminalAgent+" 198.51.100.9 "+string(actor.KindCLI), got)
		case <-time.After(300 * time.Millisecond):
			require.False(t, want, "%s, but got no mail", msg)
		}
	}

	laptop, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	lasts := terminalSignIn(t, e, u, laptop)
	assert.InDelta(t, deviceSessionTTL.Seconds(), lasts.Seconds(), 5, "session lifetime")
	wantMail(true, "the first sign-in of a key is mailed")

	terminalSignIn(t, e, u, laptop)
	wantMail(false, "the same key signing in again is not mailed")

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	terminalSignIn(t, e, u, other)
	wantMail(true, "another key is mailed")

	// Signing the account out everywhere forgets its terminals too.
	_, err = e.svc.revokeSubject(t.Context(), u.ID)
	require.NoError(t, err)
	terminalSignIn(t, e, u, laptop)
	wantMail(true, "a forgotten key is mailed again")
}
