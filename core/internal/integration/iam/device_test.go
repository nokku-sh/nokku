//go:build integration

package iam_test

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

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

const (
	terminalAgent    = "nk/1.0.0 (linux/amd64)"
	deviceSessionTTL = 30 * 24 * time.Hour
)

// devicePost sends one form request of the device flow on the workspace's host, as u when given.
func devicePost(
	ws actor.Workspace,
	handler http.HandlerFunc,
	path, remote string,
	form url.Values,
	u *db.User,
) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", terminalAgent)
	r.RemoteAddr = remote
	ctx := anon(r.Context(), ws)
	if u != nil {
		ctx = as(ctx, ws, u)
	}
	w := httptest.NewRecorder()
	handler(w, r.WithContext(ctx))
	return w
}

type deviceGrantJSON struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
}

func beginDevice(t *testing.T, e *testEnv, ws actor.Workspace) deviceGrantJSON {
	t.Helper()
	var grant deviceGrantJSON
	begun := devicePost(ws, e.svc.Device.Begin, "/auth/device", "198.51.100.9:6000", nil, nil)
	require.Equal(t, http.StatusOK, begun.Code)
	require.NoError(t, json.Unmarshal(begun.Body.Bytes(), &grant))
	return grant
}

func pollDevice(
	t *testing.T,
	e *testEnv,
	ws actor.Workspace,
	grant deviceGrantJSON,
	key *ecdsa.PrivateKey,
) *httptest.ResponseRecorder {
	t.Helper()
	const pollPath = "/auth/device/token"
	poll := httptest.NewRequest(
		http.MethodPost,
		pollPath,
		strings.NewReader(url.Values{"device_code": {grant.DeviceCode}}.Encode()),
	)
	poll.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	poll.Header.Set("User-Agent", terminalAgent)
	poll.Header.Set("DPoP", signProof(t, key, testBaseURL+pollPath, "", e.svc.DPoP.CurrentNonce(), time.Now()))
	poll.RemoteAddr = "198.51.100.9:6000"
	polled := httptest.NewRecorder()
	// The server puts these on the context of every request.
	ctx := actor.ContextWithRequestMeta(
		anon(poll.Context(), ws),
		actor.RequestMeta{Header: poll.Header, RemoteAddr: poll.RemoteAddr},
	)
	e.svc.Device.Poll(polled, poll.WithContext(ctx))
	return polled
}

// terminalSignIn runs a whole device login for u from the machine that holds key, and returns the session length.
func terminalSignIn(t *testing.T, e *testEnv, ws actor.Workspace, u *db.User, key *ecdsa.PrivateKey) time.Duration {
	t.Helper()
	grant := beginDevice(t, e, ws)
	approved := devicePost(
		ws, e.svc.Device.Verify, "/auth/device/verify", "192.0.2.1:1", url.Values{"user_code": {grant.UserCode}}, u,
	)
	require.Equal(t, http.StatusOK, approved.Code)

	polled := pollDevice(t, e, ws, grant, key)
	require.Equal(t, http.StatusOK, polled.Code, polled.Body.String())
	var token struct {
		ExpiresIn int `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(polled.Body.Bytes(), &token))
	return time.Duration(token.ExpiresIn) * time.Second
}

// The approver sees who asked for the code before approving. That is what gives a phished device code away.
func TestDeviceFlowShowsRequester(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	info := func(userCode string) (int, map[string]string) {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth/device/info?user_code="+userCode, nil)
		e.svc.Device.Info(w, r.WithContext(anon(r.Context(), o.ws)))
		var body map[string]string
		if w.Code == http.StatusOK {
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		}
		return w.Code, body
	}

	begun := devicePost(o.ws, e.svc.Device.Begin, "/auth/device", "203.0.113.7:5000", nil, nil)
	require.Equal(t, http.StatusOK, begun.Code)
	var grant struct {
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
	}
	require.NoError(t, json.Unmarshal(begun.Body.Bytes(), &grant))
	assert.Equal(t, testBaseURL+"/device", grant.VerificationURI)

	status, requester := info(strings.ToLower(grant.UserCode))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, map[string]string{"ip": "203.0.113.7", "user_agent": terminalAgent}, requester)
	status, _ = info("BCDF-GHJK")
	assert.Equal(t, http.StatusNotFound, status, "an unknown code")

	approved := devicePost(
		o.ws, e.svc.Device.Verify, "/auth/device/verify", "192.0.2.1:1", url.Values{"user_code": {grant.UserCode}},
		o.owner,
	)
	require.Equal(t, http.StatusOK, approved.Code)
	status, _ = info(grant.UserCode)
	assert.Equal(t, http.StatusNotFound, status, "a decided code")
}

// A code started on one workspace cannot be approved or redeemed on another.
func TestDeviceFlowStaysInItsWorkspace(t *testing.T) {
	e := newTestEnv(t)
	a, b := e.org(t), e.org(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	grant := beginDevice(t, e, a.ws)
	foreign := devicePost(
		b.ws, e.svc.Device.Verify, "/auth/device/verify", "192.0.2.1:1", url.Values{"user_code": {grant.UserCode}},
		b.owner,
	)
	assert.Equal(t, http.StatusBadRequest, foreign.Code, "workspace b approved a code of workspace a")

	approved := devicePost(
		a.ws, e.svc.Device.Verify, "/auth/device/verify", "192.0.2.1:1", url.Values{"user_code": {grant.UserCode}},
		a.owner,
	)
	require.Equal(t, http.StatusOK, approved.Code)
	polled := pollDevice(t, e, b.ws, grant, key)
	assert.Equal(t, http.StatusBadRequest, polled.Code, "workspace b redeemed a code of workspace a")
	assert.Zero(t, e.sessions(t, b.ws, a.owner.ID))

	polled = pollDevice(t, e, a.ws, grant, key)
	assert.Equal(t, http.StatusOK, polled.Code, polled.Body.String())
}

// A terminal is mailed once, when its key is new to the account, so the mail keeps meaning something.
func TestTerminalSignInMailsOnlyNewKeys(t *testing.T) {
	mailed := make(chan string, 4)
	e := newTestEnvWith(t, iam.Deps{SendNewLogin: func(_ context.Context, userID, _, _, label, ip string) error {
		mailed <- userID + " " + label + " " + ip
		return nil
	}})
	o := e.org(t)
	u := o.owner
	wantMail := func(want bool, msg string) {
		t.Helper()
		select {
		case got := <-mailed:
			require.True(t, want, "%s, but got a mail", msg)
			assert.Equal(t, u.ID+" "+terminalAgent+" 198.51.100.9", got)
		case <-time.After(300 * time.Millisecond):
			require.False(t, want, "%s, but got no mail", msg)
		}
	}

	laptop, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	lasts := terminalSignIn(t, e, o.ws, u, laptop)
	assert.InDelta(t, deviceSessionTTL.Seconds(), lasts.Seconds(), 5, "session lifetime")
	wantMail(true, "the first sign-in of a key is mailed")

	terminalSignIn(t, e, o.ws, u, laptop)
	wantMail(false, "the same key signing in again is not mailed")

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	terminalSignIn(t, e, o.ws, u, other)
	wantMail(true, "another key is mailed")

	// Signing the account out everywhere forgets its terminals too.
	_, err = e.svc.RevokeUser(anon(t.Context(), o.ws), u.ID)
	require.NoError(t, err)
	terminalSignIn(t, e, o.ws, u, laptop)
	wantMail(true, "a forgotten key is mailed again")
}

// Anyone can start device logins. Filling their store must not stop a browser from signing in.
func TestDeviceFloodStaysInItsStore(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	d := newPasskeyDevice()
	d.enroll(t, e, o.ws, "flood@"+testDomain())
	ctx := anon(t.Context(), o.ws)

	// The store holds 10 000 entries, two per grant.
	full := false
	for range 10_000 {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/device", nil)
		e.svc.Device.Begin(rec, r.WithContext(ctx))
		if rec.Code != http.StatusOK {
			full = true
			break
		}
	}
	require.True(t, full, "the device store takes grants without bound")

	answer, cookies := d.assertion(t, e.svc, o.ws)
	login := post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
	require.Equal(t, http.StatusOK, login.Code, "a passkey login could not finish: %s", login.Body.String())
	replay := post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusBadRequest, replay.Code, "a finished login could not be marked as spent")
}
