package iam

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

func (e *testEnv) session(t *testing.T, ws actor.Workspace, u *db.User, kind actor.Kind) (*db.Session, string) {
	t.Helper()
	sess, token, err := e.svc.IssueSession(anon(t.Context(), ws), SessionParams{
		SubjectID: u.ID, Kind: kind, Method: MethodPasskey, TTL: time.Hour,
	})
	require.NoError(t, err)
	return sess, token
}

func TestMiddlewareOnlyTrustsCookieSessions(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	_, cliToken, err := e.svc.IssueSession(anon(t.Context(), o.ws), SessionParams{
		SubjectID: o.owner.ID, Kind: actor.KindCLI, Method: MethodDevice, Binding: "jkt", TTL: time.Hour,
	})
	require.NoError(t, err)
	_, userToken := e.session(t, o.ws, o.owner, actor.KindUser)

	principal := func(r *http.Request) (actor.Principal, bool) {
		var p actor.Principal
		var ok bool
		e.svc.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			p, ok = actor.PrincipalFromContext(r.Context())
		})).ServeHTTP(httptest.NewRecorder(), r.WithContext(anon(r.Context(), o.ws)))
		return p, ok
	}

	bearer := httptest.NewRequest(http.MethodGet, "/terminal/ws", nil)
	bearer.Header.Set("Authorization", "Bearer "+cliToken)
	_, ok := principal(bearer)
	assert.False(t, ok, "a header token authenticated on the browser surface")

	cookie := httptest.NewRequest(http.MethodGet, "/terminal/ws", nil)
	cookie.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cliToken})
	_, ok = principal(cookie)
	assert.False(t, ok, "a CLI token in the session cookie authenticated")

	cookie = httptest.NewRequest(http.MethodGet, "/terminal/ws", nil)
	cookie.AddCookie(&http.Cookie{Name: sessionCookieName, Value: userToken})
	p, ok := principal(cookie)
	require.True(t, ok, "the user cookie session did not authenticate")
	assert.Equal(t, o.owner.ID, p.ID)
	assert.Equal(t, "owner", p.Role, "the principal carries the role")
}

// A session only exists on the host of its workspace.
func TestSessionIsBoundToItsWorkspace(t *testing.T) {
	e := newTestEnv(t)
	a, b := e.org(t), e.org(t)
	_, token := e.session(t, a.ws, a.owner, actor.KindUser)

	_, _, err := e.svc.AuthenticateToken(anon(t.Context(), a.ws), token)
	require.NoError(t, err)
	_, _, err = e.svc.AuthenticateToken(anon(t.Context(), b.ws), token)
	require.ErrorIs(t, err, errNoSession, "a session of workspace a authenticated on workspace b")
	_, _, err = e.svc.AuthenticateToken(t.Context(), token)
	require.ErrorIs(t, err, db.ErrWorkspaceNotPinned, "a session authenticated with no workspace")
}

func TestDeleteOwnSessionOnly(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	alice := e.user(t, o.ws, "alice@"+testDomain(), "member")
	bob := e.user(t, o.ws, "bob@"+testDomain(), "member")
	sess, _ := e.session(t, o.ws, bob, actor.KindUser)

	_ = e.svc.DeleteOwnSession(as(t.Context(), o.ws, alice), SessionHash(sess.TokenHash))
	assert.Equal(t, 1, e.sessions(t, o.ws, bob.ID), "alice deleted bob's session")
	require.NoError(t, e.svc.DeleteOwnSession(as(t.Context(), o.ws, bob), SessionHash(sess.TokenHash)))
	assert.Zero(t, e.sessions(t, o.ws, bob.ID), "bob could not delete his own session")
}

func TestLogoutRevokesBoundSession(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tp, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	_, token, err := e.svc.IssueSession(ctx, SessionParams{
		SubjectID: o.owner.ID, Kind: actor.KindCLI, Method: MethodDevice,
		Binding: base64.RawURLEncoding.EncodeToString(tp), TTL: time.Hour,
	})
	require.NoError(t, err)
	const procedure = "/nokku.v1.AuthService/Logout"
	header := http.Header{}
	header.Set("Authorization", "DPoP "+token)

	err = e.svc.Logout(ctx, header, procedure)
	require.ErrorIs(t, err, ErrDPoPRequired, "logout without proof")
	assert.Equal(t, 1, e.sessions(t, o.ws, o.owner.ID), "a token without its proof ended the session")

	proof := func() string {
		return signProof(t, key, testBaseURL+procedure, DPoPATH(token), e.svc.DPoP.CurrentNonce(), time.Now())
	}
	header.Set("DPoP", proof())
	require.NoError(t, e.svc.Logout(ctx, header, procedure))
	assert.Zero(t, e.sessions(t, o.ws, o.owner.ID))
	// A second logout with the dead token still succeeds.
	header.Set("DPoP", proof())
	require.NoError(t, e.svc.Logout(ctx, header, procedure))
}

func TestSessionRecordsDevice(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	header := http.Header{"User-Agent": {"Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"}}
	ctx := actor.ContextWithRequestMeta(
		anon(t.Context(), o.ws),
		actor.RequestMeta{Header: header, RemoteAddr: "203.0.113.7:4242"},
	)

	sess, _, err := e.svc.IssueSession(ctx, SessionParams{
		SubjectID: o.owner.ID, Kind: actor.KindUser, Method: MethodPasskey, TTL: time.Hour,
	})
	require.NoError(t, err)
	assert.Equal(t, header.Get("User-Agent"), sess.UserAgent)
	assert.Equal(t, "203.0.113.7", sess.Ip)
	assert.Equal(t, o.ws.ID, sess.WorkspaceID)
}

func TestInactiveUserLosesCLISession(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := e.user(t, o.ws, "user@"+testDomain(), "member")
	_, token := e.session(t, o.ws, u, actor.KindCLI)
	ctx := anon(t.Context(), o.ws)
	_, _, err := e.svc.AuthenticateToken(ctx, token)
	require.NoError(t, err)

	require.NoError(t, e.conn.Sys().SetUserActive(t.Context(), &db.SetUserActiveParams{ID: u.ID, Active: false}))
	_, _, err = e.svc.AuthenticateToken(ctx, token)
	require.ErrorIs(t, err, ErrInactive)
}

// The session row has to go with the account.
func TestDeletedUserLosesSessions(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := e.user(t, o.ws, "user@"+testDomain(), "member")
	_, token := e.session(t, o.ws, u, actor.KindCLI)
	ctx := anon(t.Context(), o.ws)
	_, _, err := e.svc.AuthenticateToken(ctx, token)
	require.NoError(t, err)

	require.NoError(t, e.conn.Sys().DeleteUser(t.Context(), u.ID))
	_, _, err = e.svc.AuthenticateToken(ctx, token)
	require.Error(t, err, "the session of a deleted account still authenticates")
}

func TestOwnerCannotDeleteThemselves(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	member := e.user(t, o.ws, "m@"+testDomain(), "member")
	require.ErrorIs(t, e.svc.DeleteSelf(as(t.Context(), o.ws, o.owner)), ErrOwner)
	require.NoError(t, e.svc.DeleteSelf(as(t.Context(), o.ws, member)))
	assert.Nil(t, e.userByEmail(t, o.ws, member.Email))
}

func TestEmailChange(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	oldEmail, newEmail := "old@"+testDomain(), "new@"+testDomain()
	u := e.user(t, o.ws, oldEmail, "member")
	taken := e.user(t, o.ws, "taken@"+testDomain(), "member")
	ctx := as(t.Context(), o.ws, u)

	_, _, err := e.svc.RequestEmailChange(ctx, u, oldEmail)
	require.ErrorIs(t, err, ErrSameEmail)
	_, _, err = e.svc.RequestEmailChange(ctx, u, taken.Email)
	require.ErrorIs(t, err, ErrEmailTaken)

	// A second request replaces the first, its link confirms nothing.
	stale, _, err := e.svc.RequestEmailChange(ctx, u, "typo@"+testDomain())
	require.NoError(t, err)
	confirm, cancel, err := e.svc.RequestEmailChange(ctx, u, " "+strings.ToUpper(newEmail))
	require.NoError(t, err)
	require.ErrorIs(t, e.svc.ConfirmEmailChange(ctx, stale), ErrInvalidToken, "stale link")
	assert.Equal(t, newEmail, e.svc.PendingEmail(ctx, u.ID))
	require.NotNil(t, e.userByEmail(t, o.ws, oldEmail), "the address changed before the new one was confirmed")
	require.ErrorIs(t, e.svc.ConfirmEmailChange(ctx, cancel), ErrInvalidToken, "the cancel link is not a confirm link")

	require.NoError(t, e.svc.ConfirmEmailChange(ctx, confirm))
	got := e.userByEmail(t, o.ws, newEmail)
	require.NotNil(t, got)
	assert.Equal(t, u.ID, got.ID)
	assert.Empty(t, e.svc.PendingEmail(ctx, u.ID))
	require.ErrorIs(t, e.svc.ConfirmEmailChange(ctx, confirm), ErrInvalidToken, "second confirm")

	// The old inbox undoes the change and signs everyone out.
	_, session := e.session(t, o.ws, u, actor.KindUser)
	require.NoError(t, e.svc.CancelEmailChange(ctx, cancel))
	got = e.userByEmail(t, o.ws, oldEmail)
	require.NotNil(t, got)
	assert.Equal(t, u.ID, got.ID)
	_, err = e.svc.verifySession(ctx, session)
	require.Error(t, err, "a session survived the revert")
	require.ErrorIs(t, e.svc.CancelEmailChange(ctx, cancel), ErrInvalidToken, "second revert")
}

func TestEmailChangeCancelBeforeConfirm(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := e.user(t, o.ws, "old@"+testDomain(), "member")
	ctx := as(t.Context(), o.ws, u)
	confirm, cancel, err := e.svc.RequestEmailChange(ctx, u, "new@"+testDomain())
	require.NoError(t, err)
	_, session := e.session(t, o.ws, u, actor.KindUser)

	require.NoError(t, e.svc.CancelEmailChange(ctx, cancel))
	require.ErrorIs(t, e.svc.ConfirmEmailChange(ctx, confirm), ErrInvalidToken, "confirm after cancel")
	require.NotNil(t, e.userByEmail(t, o.ws, u.Email), "cancel changed the address")
	// Nothing changed yet, so nobody is signed out.
	_, err = e.svc.verifySession(ctx, session)
	require.NoError(t, err, "cancel of a pending change ended the session")
}

// An identity provider owns the address of the accounts it vouches for.
func TestEmailChangeRefusedForManagedAccounts(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := e.user(t, o.ws, "managed@"+testDomain(), "member")
	e.putCredential(t, o.ws, db.UpsertCredentialParams{
		ID: "okta:sub", UserID: u.ID, Type: string(MethodOIDC), Provider: "okta", Subject: "sub", Data: []byte{},
	})
	_, _, err := e.svc.RequestEmailChange(as(t.Context(), o.ws, u), u, "other@"+testDomain())
	require.ErrorIs(t, err, ErrManagedAccount)
}

// A browser is mailed once, when it is new to the account, and what
// remembers it is no way to sign in.
func TestBrowserIsRememberedAndNeverSignsIn(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := o.owner
	mailed := make(chan string, 4)
	e.svc.sendNewLogin = func(_ context.Context, userID, _, _, name, ip string) error {
		mailed <- userID + " " + name + " " + ip
		return nil
	}
	wantMail := func(want bool, msg string) {
		t.Helper()
		select {
		case got := <-mailed:
			require.True(t, want, "%s, but got a mail", msg)
			assert.Equal(t, u.ID+" Firefox on Linux 203.0.113.7", got)
		case <-time.After(300 * time.Millisecond):
			require.False(t, want, "%s, but got no mail", msg)
		}
	}
	ctx := anon(t.Context(), o.ws)
	header := http.Header{"User-Agent": {"Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"}}
	const addr = "203.0.113.7:4242"

	cookie := e.svc.RememberDevice(ctx, header, addr, u)
	require.NotNil(t, cookie, "a new browser gets the device cookie")
	wantMail(true, "the first sign-in of a browser is mailed")

	header.Set("Cookie", cookie.Name+"="+cookie.Value)
	assert.Nil(t, e.svc.RememberDevice(ctx, header, addr, u), "a known browser keeps its cookie")
	wantMail(false, "the same browser signing in again is not mailed")

	devices, err := e.svc.ListDevices(as(ctx, o.ws, u))
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, header.Get("User-Agent"), devices[0].UserAgent)
	assert.Equal(t, "203.0.113.7", devices[0].Ip)

	// The cookie only names the device, it opens nothing.
	assert.Zero(t, e.sessions(t, o.ws, u.ID), "remembering a device issued a session")
	for _, h := range []http.Header{
		{"Authorization": {"Bearer " + cookie.Value}},
		{"Cookie": {sessionCookieName + "=" + cookie.Value}},
	} {
		_, _, err := e.svc.Authenticate(ctx, h, "/nokku.v1.UtilService/Whoami")
		require.Error(t, err, "the device cookie signed in")
	}

	// Another account on the same browser is new there.
	other := e.user(t, o.ws, "other@"+testDomain(), "member")
	e.svc.sendNewLogin = nil
	assert.NotNil(t, e.svc.RememberDevice(ctx, header, addr, other), "a device of one account is known to another")

	// Signing the account out everywhere forgets its devices too.
	_, err = e.svc.RevokeUser(ctx, u.ID)
	require.NoError(t, err)
	devices, err = e.svc.ListDevices(as(ctx, o.ws, u))
	require.NoError(t, err)
	assert.Empty(t, devices)
	assert.NotNil(t, e.svc.RememberDevice(ctx, header, addr, u), "a forgotten browser is new again")
}

// The sessions list shows when a session was last used. The stamp moves with
// authenticated requests, at most once a minute.
func TestSessionActivityIsNotedOnceAMinute(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	now := time.Now()
	e.svc.now = func() time.Time { return now }
	sess, token := e.session(t, o.ws, o.owner, actor.KindUser)
	ctx := anon(t.Context(), o.ws)
	header := http.Header{"Authorization": {"Bearer " + token}}
	lastSeen := func() time.Time {
		t.Helper()
		var row *db.Session
		require.NoError(t, e.in(t, o.ws, func(q *db.Queries) (err error) {
			row, err = q.GetSession(t.Context(), sess.TokenHash)
			return err
		}))
		require.NotNil(t, row.LastSeenAt)
		return *row.LastSeenAt
	}
	issued := lastSeen()

	now = now.Add(30 * time.Second)
	_, _, err := e.svc.Authenticate(ctx, header, "/nokku.v1.UtilService/Whoami")
	require.NoError(t, err)
	assert.Equal(t, issued, lastSeen(), "a request within the minute wrote the stamp")

	now = now.Add(time.Minute)
	_, _, err = e.svc.Authenticate(ctx, header, "/nokku.v1.UtilService/Whoami")
	require.NoError(t, err)
	assert.WithinDuration(t, now, lastSeen(), time.Millisecond, "a later request did not move the stamp")
}
