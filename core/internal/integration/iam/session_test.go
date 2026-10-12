//go:build integration

package iam_test

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

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	nkcrypto "github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

func (e *testEnv) session(t *testing.T, ws actor.Workspace, u *db.User, kind actor.Kind) (*db.AccessToken, string) {
	t.Helper()
	sess, token, err := e.svc.IssueToken(anon(t.Context(), ws), iam.TokenParams{
		SubjectID: u.ID, Kind: kind, Method: iam.MethodPasskey, TTL: time.Hour,
	})
	require.NoError(t, err)
	return sess, token
}

func TestMiddlewareOnlyTrustsCookieSessions(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	_, cliToken, err := e.svc.IssueToken(anon(t.Context(), o.ws), iam.TokenParams{
		SubjectID: o.owner.ID, Kind: actor.KindCLI, Method: iam.MethodDevice, Binding: "jkt", TTL: time.Hour,
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
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER, p.Role, "the principal carries the role")
}

// A session only exists on the host of its workspace.
func TestSessionIsBoundToItsWorkspace(t *testing.T) {
	e := newTestEnv(t)
	a, b := e.org(t), e.org(t)
	_, token := e.session(t, a.ws, a.owner, actor.KindUser)

	_, _, err := e.svc.AuthenticateToken(anon(t.Context(), a.ws), token)
	require.NoError(t, err)
	_, _, err = e.svc.AuthenticateToken(anon(t.Context(), b.ws), token)
	require.Error(t, err, "a session of workspace a authenticated on workspace b")
	_, _, err = e.svc.AuthenticateToken(t.Context(), token)
	require.ErrorIs(t, err, db.ErrWorkspaceNotPinned, "a session authenticated with no workspace")
}

func TestDeleteOwnSessionOnly(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	alice := e.user(t, o.ws, "alice@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	bob := e.user(t, o.ws, "bob@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	sess, _ := e.session(t, o.ws, bob, actor.KindUser)

	_ = e.svc.DeleteOwnSession(as(t.Context(), o.ws, alice), sess.ID)
	assert.Equal(t, 1, e.sessions(t, o.ws, bob.ID), "alice deleted bob's session")
	require.NoError(t, e.svc.DeleteOwnSession(as(t.Context(), o.ws, bob), sess.ID))
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
	_, token, err := e.svc.IssueToken(ctx, iam.TokenParams{
		SubjectID: o.owner.ID, Kind: actor.KindCLI, Method: iam.MethodDevice,
		Binding: base64.RawURLEncoding.EncodeToString(tp), TTL: time.Hour,
	})
	require.NoError(t, err)
	const procedure = "/nokku.v1.AuthService/Logout"
	header := http.Header{}
	header.Set("Authorization", "DPoP "+token)

	err = e.svc.Logout(ctx, header, procedure)
	require.ErrorIs(t, err, iam.ErrDPoPRequired, "logout without proof")
	assert.Equal(t, 1, e.sessions(t, o.ws, o.owner.ID), "a token without its proof ended the session")

	proof := func() string {
		return signProof(t, key, testBaseURL+procedure, iam.DPoPATH(token), e.svc.DPoP.CurrentNonce(), time.Now())
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

	sess, _, err := e.svc.IssueToken(ctx, iam.TokenParams{
		SubjectID: o.owner.ID, Kind: actor.KindUser, Method: iam.MethodPasskey, TTL: time.Hour,
	})
	require.NoError(t, err)
	assert.Equal(t, header.Get("User-Agent"), sess.UserAgent)
	assert.Equal(t, "203.0.113.7", sess.Ip)
	assert.Equal(t, o.ws.ID, sess.WorkspaceID)
}

func TestInactiveUserLosesCLISession(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := e.user(t, o.ws, "user@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	_, token := e.session(t, o.ws, u, actor.KindCLI)
	ctx := anon(t.Context(), o.ws)
	_, _, err := e.svc.AuthenticateToken(ctx, token)
	require.NoError(t, err)

	require.NoError(t, e.conn.Sys().SetUserActive(t.Context(), &db.SetUserActiveParams{ID: u.ID, Active: false}))
	_, _, err = e.svc.AuthenticateToken(ctx, token)
	require.ErrorIs(t, err, iam.ErrInactive)
}

// The session row has to go with the account.
func TestDeletedUserLosesSessions(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := e.user(t, o.ws, "user@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
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
	member := e.user(t, o.ws, "m@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	require.ErrorIs(t, e.svc.DeleteSelf(as(t.Context(), o.ws, o.owner)), iam.ErrOwner)
	require.NoError(t, e.svc.DeleteSelf(as(t.Context(), o.ws, member)))
	assert.Nil(t, e.userByEmail(t, o.ws, member.Email))
}

func TestEmailChange(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	oldEmail, newEmail := "old@"+testDomain(), "new@"+testDomain()
	u := e.user(t, o.ws, oldEmail, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	taken := e.user(t, o.ws, "taken@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	ctx := as(t.Context(), o.ws, u)

	_, _, err := e.svc.RequestEmailChange(ctx, u, oldEmail)
	require.ErrorIs(t, err, iam.ErrSameEmail)
	_, _, err = e.svc.RequestEmailChange(ctx, u, taken.Email)
	require.ErrorIs(t, err, iam.ErrEmailTaken)

	// A second request replaces the first, its link confirms nothing.
	stale, _, err := e.svc.RequestEmailChange(ctx, u, "typo@"+testDomain())
	require.NoError(t, err)
	confirm, cancel, err := e.svc.RequestEmailChange(ctx, u, " "+strings.ToUpper(newEmail))
	require.NoError(t, err)
	require.ErrorIs(t, e.svc.ConfirmEmailChange(ctx, stale), iam.ErrInvalidToken, "stale link")
	assert.Equal(t, newEmail, e.svc.PendingEmail(ctx, u.ID))
	require.NotNil(t, e.userByEmail(t, o.ws, oldEmail), "the address changed before the new one was confirmed")
	require.ErrorIs(
		t,
		e.svc.ConfirmEmailChange(ctx, cancel),
		iam.ErrInvalidToken,
		"the cancel link is not a confirm link",
	)

	require.NoError(t, e.svc.ConfirmEmailChange(ctx, confirm))
	got := e.userByEmail(t, o.ws, newEmail)
	require.NotNil(t, got)
	assert.Equal(t, u.ID, got.ID)
	assert.Empty(t, e.svc.PendingEmail(ctx, u.ID))
	require.ErrorIs(t, e.svc.ConfirmEmailChange(ctx, confirm), iam.ErrInvalidToken, "second confirm")

	// The old inbox undoes the change and signs everyone out.
	_, session := e.session(t, o.ws, u, actor.KindUser)
	require.NoError(t, e.svc.CancelEmailChange(ctx, cancel))
	got = e.userByEmail(t, o.ws, oldEmail)
	require.NotNil(t, got)
	assert.Equal(t, u.ID, got.ID)
	_, _, err = e.svc.AuthenticateToken(ctx, session)
	require.Error(t, err, "a session survived the revert")
	require.ErrorIs(t, e.svc.CancelEmailChange(ctx, cancel), iam.ErrInvalidToken, "second revert")
}

func TestEmailChangeCancelBeforeConfirm(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := e.user(t, o.ws, "old@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	ctx := as(t.Context(), o.ws, u)
	confirm, cancel, err := e.svc.RequestEmailChange(ctx, u, "new@"+testDomain())
	require.NoError(t, err)
	_, session := e.session(t, o.ws, u, actor.KindUser)

	require.NoError(t, e.svc.CancelEmailChange(ctx, cancel))
	require.ErrorIs(t, e.svc.ConfirmEmailChange(ctx, confirm), iam.ErrInvalidToken, "confirm after cancel")
	require.NotNil(t, e.userByEmail(t, o.ws, u.Email), "cancel changed the address")
	// Nothing changed yet, so nobody is signed out.
	_, _, err = e.svc.AuthenticateToken(ctx, session)
	require.NoError(t, err, "cancel of a pending change ended the session")
}

// An identity provider owns the address of the accounts it vouches for.
func TestEmailChangeRefusedForManagedAccounts(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	u := e.user(t, o.ws, "managed@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	e.putCredential(t, o.ws, db.UpsertCredentialParams{
		ID: "okta:sub", UserID: u.ID, Type: string(iam.MethodOIDC), Provider: "okta", Subject: "sub", Data: []byte{},
	})
	_, _, err := e.svc.RequestEmailChange(as(t.Context(), o.ws, u), u, "other@"+testDomain())
	require.ErrorIs(t, err, iam.ErrManagedAccount)
}

// A browser is mailed once, when it is new to the account, and what remembers it is no way to sign in.
func TestBrowserIsRememberedAndNeverSignsIn(t *testing.T) {
	mailed := make(chan string, 4)
	e := newTestEnvWith(t, iam.Deps{SendNewLogin: func(_ context.Context, userID, _, _, name, ip string) error {
		mailed <- userID + " " + name + " " + ip
		return nil
	}})
	o := e.org(t)
	u := o.owner
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

	// Another account on the same browser gets a cookie of its own. Under one name the browser would drop the first.
	other := e.user(t, o.ws, "other@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	second := e.svc.RememberDevice(ctx, header, addr, other)
	require.NotNil(t, second, "a device of one account is known to another")
	require.NotEqual(t, cookie.Name, second.Name, "the second account's cookie replaces the first one's")
	header.Set("Cookie", cookie.Name+"="+cookie.Value+"; "+second.Name+"="+second.Value)
	assert.Nil(t, e.svc.RememberDevice(ctx, header, addr, u), "another account signing in made the browser new")
	assert.Nil(t, e.svc.RememberDevice(ctx, header, addr, other), "the second account forgot the browser")

	// Signing the account out everywhere forgets its devices too.
	_, err = e.svc.RevokeUser(ctx, u.ID)
	require.NoError(t, err)
	devices, err = e.svc.ListDevices(as(ctx, o.ws, u))
	require.NoError(t, err)
	assert.Empty(t, devices)
	assert.NotNil(t, e.svc.RememberDevice(ctx, header, addr, u), "a forgotten browser is new again")
}

// The stamp moves with authenticated requests, at most once a minute.
func TestSessionActivityIsNotedOnceAMinute(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	sess, token := e.session(t, o.ws, o.owner, actor.KindUser)
	ctx := anon(t.Context(), o.ws)
	header := http.Header{"Authorization": {"Bearer " + token}}
	lastSeen := func() time.Time {
		t.Helper()
		var row *db.AccessToken
		require.NoError(t, e.in(t, o.ws, func(q *db.Queries) (err error) {
			row, err = q.GetAccessToken(t.Context(), sess.TokenHash)
			return err
		}))
		require.NotNil(t, row.LastSeenAt)
		return *row.LastSeenAt
	}
	// seen moves the stamp into the past, the clock of the service is not ours to move.
	seen := func(ago time.Duration) time.Time {
		t.Helper()
		at := time.Now().Add(-ago)
		require.NoError(t, e.in(t, o.ws, func(q *db.Queries) error {
			return q.TouchAccessToken(t.Context(), &db.TouchAccessTokenParams{ID: sess.ID, LastSeenAt: &at})
		}))
		return at
	}

	recent := seen(30 * time.Second)
	_, _, err := e.svc.Authenticate(ctx, header, "/nokku.v1.UtilService/Whoami")
	require.NoError(t, err)
	assert.WithinDuration(t, recent, lastSeen(), time.Millisecond, "a request within the minute wrote the stamp")

	seen(time.Minute)
	_, _, err = e.svc.Authenticate(ctx, header, "/nokku.v1.UtilService/Whoami")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), lastSeen(), 5*time.Second, "a later request did not move the stamp")
}

func (e *testEnv) serviceAccount(t *testing.T, ws actor.Workspace) string {
	t.Helper()
	var id string
	require.NoError(t, e.in(t, ws, func(q *db.Queries) (err error) {
		id, err = q.CreateServiceAccount(t.Context(), &db.CreateServiceAccountParams{
			Name: "ci-" + strings.ToLower(ws.Slug),
			Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		})
		return err
	}))
	return id
}

func (e *testEnv) key(t *testing.T, ws actor.Workspace, saID string) (*db.AccessToken, string) {
	t.Helper()
	tok, secret, err := e.svc.IssueToken(anon(t.Context(), ws), iam.TokenParams{
		SubjectID: saID, Kind: actor.KindServiceAccount, Method: iam.MethodToken, Label: "deploy",
	})
	require.NoError(t, err)
	return tok, secret
}

// A key with a bad checksum fails before the lookup, so with no workspace pinned the pin is never missed.
func TestBadChecksumNeverReachesTheDatabase(t *testing.T) {
	e := newTestEnv(t)
	whoami := func(token string) error {
		_, _, err := e.svc.Authenticate(
			t.Context(), http.Header{"Authorization": {"Bearer " + token}}, "/nokku.v1.UtilService/Whoami",
		)
		return err
	}
	o := e.org(t)
	_, secret := e.key(t, o.ws, e.serviceAccount(t, o.ws))
	err := whoami(secret[:len(secret)-1] + "?")
	require.Error(t, err)
	require.NotErrorIs(t, err, db.ErrWorkspaceNotPinned, "a bad checksum was looked up")
	require.ErrorIs(t, whoami(secret), db.ErrWorkspaceNotPinned, "a good checksum is looked up")
}

// A SCIM token provisions accounts and nothing else. On a connect call it is no credential at all.
func TestSCIMTokenIsNoConnectCredential(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	_, token, err := e.svc.IssueToken(as(t.Context(), o.ws, o.owner), iam.TokenParams{
		Kind: actor.KindSCIM, Method: iam.MethodSCIM, Label: "okta",
	})
	require.NoError(t, err)
	ctx := anon(t.Context(), o.ws)

	p, _, err := e.svc.AuthenticateToken(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, actor.KindSCIM, p.Kind)
	_, _, err = e.svc.Authenticate(
		ctx,
		http.Header{"Authorization": {"Bearer " + token}},
		"/nokku.v1.UtilService/Whoami",
	)
	require.Error(t, err, "a SCIM token authenticated a connect call")
}

// A key is not a session. A script that calls Logout keeps it.
func TestLogoutLeavesServiceAccountTokenAlone(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	_, secret := e.key(t, o.ws, e.serviceAccount(t, o.ws))
	ctx := anon(t.Context(), o.ws)
	header := http.Header{"Authorization": {"Bearer " + secret}}

	require.NoError(t, e.svc.Logout(ctx, header, "/nokku.v1.AuthService/Logout"))
	p, _, err := e.svc.AuthenticateToken(ctx, secret)
	require.NoError(t, err, "logout ended the key")
	assert.Equal(t, actor.KindServiceAccount, p.Kind)
}

// An expired key fails and is gone with its first use after the expiry.
func TestExpiredTokenIsDeletedOnUse(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	saID := e.serviceAccount(t, o.ws)
	secret, hash := nkcrypto.NewKey(nkcrypto.KeyPrefixServiceAccount)
	require.NoError(t, e.in(t, o.ws, func(q *db.Queries) error {
		_, err := q.CreateAccessToken(t.Context(), &db.CreateAccessTokenParams{
			TokenHash: hash, Kind: string(actor.KindServiceAccount), SubjectID: &saID,
			Method: string(iam.MethodToken), ExpiresAt: new(time.Now().Add(-time.Minute)),
		})
		return err
	}))

	_, _, err := e.svc.AuthenticateToken(anon(t.Context(), o.ws), secret)
	require.Error(t, err, "an expired key signed in")
	var left []*db.AccessToken
	require.NoError(t, e.in(t, o.ws, func(q *db.Queries) (err error) {
		left, err = q.ListServiceAccountTokens(t.Context(), saID)
		return err
	}))
	assert.Empty(t, left, "the expired key is still listed")
}
