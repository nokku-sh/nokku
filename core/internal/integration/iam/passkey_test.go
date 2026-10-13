//go:build integration

package iam_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// passkeyDevice is a browser with a software authenticator, answering the real handlers the way a device would.
type passkeyDevice struct {
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

func newPasskeyDevice() *passkeyDevice {
	return &passkeyDevice{
		rp:   virtualwebauthn.RelyingParty{ID: "nokku.test", Name: "Test", Origin: testBaseURL},
		auth: virtualwebauthn.NewAuthenticator(),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
}

// post calls one handler with the cookies the step before left behind.
func post(ctx context.Context, h http.HandlerFunc, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader(body))
	if strings.HasPrefix(body, "{") {
		r.Header.Set("Content-Type", "application/json")
	} else {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec
}

// attest answers a registration the server started.
func (d *passkeyDevice) attest(t *testing.T, begin *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusOK, begin.Code, begin.Body.String())
	options, err := virtualwebauthn.ParseAttestationOptions(begin.Body.String())
	require.NoError(t, err)
	// A passkey hands the account id back at sign-in.
	d.auth.Options.UserHandle = []byte(options.UserID)
	return virtualwebauthn.CreateAttestationResponse(d.rp, d.auth, d.cred, *options)
}

// assertion starts a sign-in on ws and answers it. The cookies carry the ceremony.
func (d *passkeyDevice) assertion(t *testing.T, svc *iam.Service, ws actor.Workspace) (string, []*http.Cookie) {
	t.Helper()
	begin := post(anon(t.Context(), ws), svc.Passkey.BeginLogin, "", nil)
	require.Equal(t, http.StatusOK, begin.Code, begin.Body.String())
	options, err := virtualwebauthn.ParseAssertionOptions(begin.Body.String())
	require.NoError(t, err)
	return virtualwebauthn.CreateAssertionResponse(d.rp, d.auth, d.cred, *options), begin.Result().Cookies()
}

// signUp takes an invite with the device's passkey and lands signed in.
func (d *passkeyDevice) signUp(t *testing.T, e *testEnv, ws actor.Workspace, invite, email string) *db.User {
	t.Helper()
	ctx := anon(t.Context(), ws)
	form := url.Values{"invite": {invite}, "email": {email}, "name": {"New"}}.Encode()
	begin := post(ctx, e.svc.Passkey.BeginSignup, form, nil)
	finish := post(ctx, e.svc.Passkey.FinishSignup, d.attest(t, begin), begin.Result().Cookies())
	require.Equal(t, http.StatusOK, finish.Code, finish.Body.String())
	u := e.userByEmail(t, ws, email)
	require.NotNil(t, u, "the signup created no account")
	return u
}

func hasCookie(rec *httptest.ResponseRecorder, name string) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

// The invite is spent, and neither ceremony can be played a second time.
func TestPasskeySignupThenLogin(t *testing.T) {
	e := newTestEnv(t)
	d := newPasskeyDevice()
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	invite := e.invite(t, o.ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER, 1)
	email := "new@" + testDomain()

	bogus := post(ctx, e.svc.Passkey.BeginSignup, url.Values{"invite": {"nope"}, "email": {email}}.Encode(), nil)
	assert.Equal(t, http.StatusBadRequest, bogus.Code, "a signup without a valid invite started")

	form := url.Values{"invite": {invite}, "email": {email}, "name": {"New"}}.Encode()
	begin := post(ctx, e.svc.Passkey.BeginSignup, form, nil)
	attestation := d.attest(t, begin)
	finish := post(ctx, e.svc.Passkey.FinishSignup, attestation, begin.Result().Cookies())
	require.Equal(t, http.StatusOK, finish.Code, finish.Body.String())
	assert.True(t, hasCookie(finish, sessionCookieName), "the signup signs in")

	u := e.userByEmail(t, o.ws, email)
	require.NotNil(t, u)
	assert.Equal(t, "New", u.Name)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER, u.Role, "the role comes from the invite")
	assert.Equal(t, 1, e.passkeys(t, o.ws, u.ID))
	assert.Equal(t, 1, e.sessions(t, o.ws, u.ID))
	_, err := e.svc.LookupInvite(ctx, invite)
	require.ErrorIs(t, err, iam.ErrInviteSpent, "the one-use invite survived")

	replay := post(ctx, e.svc.Passkey.FinishSignup, attestation, begin.Result().Cookies())
	assert.Equal(t, http.StatusBadRequest, replay.Code, "a finished signup ran again: %s", replay.Body.String())

	answer, cookies := d.assertion(t, e.svc, o.ws)
	login := post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	assert.True(t, hasCookie(login, sessionCookieName), "the sign-in sets a session")
	assert.Equal(t, 2, e.sessions(t, o.ws, u.ID))

	replay = post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusBadRequest, replay.Code, "a captured sign-in ran again: %s", replay.Body.String())
	assert.Equal(t, 2, e.sessions(t, o.ws, u.ID), "the replay opened a session")
}

// A passkey made for one workspace is unknown on another, even when both answer on the same host in tests.
func TestPasskeyStaysInItsWorkspace(t *testing.T) {
	e := newTestEnv(t)
	d := newPasskeyDevice()
	a, b := e.org(t), e.org(t)
	u := d.signUp(t, e, a.ws, e.invite(t, a.ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, 0), "p@"+testDomain())

	answer, cookies := d.assertion(t, e.svc, b.ws)
	rec := post(anon(t.Context(), b.ws), e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "workspace b accepted a passkey of workspace a")
	assert.Zero(t, e.sessions(t, b.ws, u.ID))
}

// What a phishing page, another ceremony or a guessed key hands in is refused, and the real device still gets in.
func TestPasskeyLoginRefusesForgedAnswers(t *testing.T) {
	e := newTestEnv(t)
	d := newPasskeyDevice()
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	u := d.signUp(t, e, o.ws, e.invite(t, o.ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, 0), "forged@"+testDomain())
	before := e.sessions(t, o.ws, u.ID)

	otherSite := *d
	otherSite.rp.Origin = "http://nokku.test.evil.example"
	unverified := *d
	unverified.auth.Options.UserNotVerified = true
	// The credential id and the account id are not secret, the key is.
	guessedKey := *d
	guessedKey.cred = virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	guessedKey.cred.ID = d.cred.ID

	for name, device := range map[string]*passkeyDevice{
		"an answer made for another origin":      &otherSite,
		"an answer without a PIN or fingerprint": &unverified,
		"an answer signed by another key":        &guessedKey,
	} {
		answer, cookies := device.assertion(t, e.svc, o.ws)
		rec := post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
	}

	answer, _ := d.assertion(t, e.svc, o.ws)
	_, cookies := d.assertion(t, e.svc, o.ws)
	rec := post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an answer to another ceremony: %s", rec.Body.String())

	rec = post(ctx, e.svc.Passkey.FinishLogin, answer, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an answer without its ceremony: %s", rec.Body.String())
	assert.Equal(t, before, e.sessions(t, o.ws, u.ID), "a refused answer opened a session")

	answer, cookies = d.assertion(t, e.svc, o.ws)
	rec = post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusOK, rec.Code, "the real device: %s", rec.Body.String())
}

// Adding a passkey needs a session, and the ceremony belongs to the account that started it.
func TestPasskeyRegistrationBelongsToItsAccount(t *testing.T) {
	e := newTestEnv(t)
	d := newPasskeyDevice()
	o := e.org(t)
	alice := e.user(t, o.ws, "alice@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	mallory := e.user(t, o.ws, "mallory@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)

	anonymous := post(anon(t.Context(), o.ws), e.svc.Passkey.BeginRegistration, "", nil)
	assert.Equal(t, http.StatusUnauthorized, anonymous.Code, anonymous.Body.String())

	begin := post(as(t.Context(), o.ws, alice), e.svc.Passkey.BeginRegistration, "", nil)
	attestation := d.attest(t, begin)

	stolen := post(
		as(t.Context(), o.ws, mallory),
		e.svc.Passkey.FinishRegistration,
		attestation,
		begin.Result().Cookies(),
	)
	assert.Equal(
		t,
		http.StatusBadRequest,
		stolen.Code,
		"another account finished the ceremony: %s",
		stolen.Body.String(),
	)
	assert.Zero(t, e.passkeys(t, o.ws, mallory.ID))

	finish := post(
		as(t.Context(), o.ws, alice),
		e.svc.Passkey.FinishRegistration,
		attestation,
		begin.Result().Cookies(),
	)
	require.Equal(t, http.StatusOK, finish.Code, finish.Body.String())
	assert.Equal(t, 1, e.passkeys(t, o.ws, alice.ID))

	answer, cookies := d.assertion(t, e.svc, o.ws)
	login := post(anon(t.Context(), o.ws), e.svc.Passkey.FinishLogin, answer, cookies)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	assert.Equal(t, 1, e.sessions(t, o.ws, alice.ID))
	assert.Zero(t, e.sessions(t, o.ws, mallory.ID))
}

// Enforced SSO leaves the owner the passkey, the way in to fix a broken provider.
func TestEnforcedSSOLeavesTheOwnerThePasskey(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	member := nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER
	ownerKey, memberKey := newPasskeyDevice(), newPasskeyDevice()
	next := ownerKey.signUp(t, e, o.ws, e.invite(t, o.ws, member, 0), "next-owner@"+testDomain())
	memberKey.signUp(t, e, o.ws, e.invite(t, o.ws, member, 0), "member@"+testDomain())
	require.NoError(t, e.in(t, o.ws, func(q *db.Queries) error {
		_, err := q.TransferOwnership(t.Context(), next.ID)
		return err
	}))
	e.setEnforceSSO(t, o.ws, true)
	ctx := anon(t.Context(), o.ws)

	answer, cookies := memberKey.assertion(t, e.svc, o.ws)
	refused := post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusForbidden, refused.Code, "a member got past enforced SSO: %s", refused.Body.String())

	answer, cookies = ownerKey.assertion(t, e.svc, o.ws)
	login := post(ctx, e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusOK, login.Code, "the owner is locked out: %s", login.Body.String())
}
