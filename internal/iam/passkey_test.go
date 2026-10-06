package iam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/db"
)

// passkeyDevice is a browser with a software authenticator. It answers the
// ceremonies of the real handlers the way a device would.
type passkeyDevice struct {
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

func newPasskeyDevice() *passkeyDevice {
	return &passkeyDevice{
		rp:   virtualwebauthn.RelyingParty{ID: "nokku.test", Name: "Nokku", Origin: testBaseURL},
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

// assertion starts a sign-in and answers it. The cookies carry the ceremony.
func (d *passkeyDevice) assertion(t *testing.T, svc *Service) (string, []*http.Cookie) {
	t.Helper()
	begin := post(t.Context(), svc.Passkey.BeginLogin, "", nil)
	require.Equal(t, http.StatusOK, begin.Code, begin.Body.String())
	options, err := virtualwebauthn.ParseAssertionOptions(begin.Body.String())
	require.NoError(t, err)
	return virtualwebauthn.CreateAssertionResponse(d.rp, d.auth, d.cred, *options), begin.Result().Cookies()
}

// signUp creates an account with the device's passkey, email not verified yet.
func (d *passkeyDevice) signUp(t *testing.T, e *testEnv) *db.User {
	t.Helper()
	email := "passkey@" + testDomain()
	begin := post(t.Context(), e.svc.Passkey.BeginSignup, url.Values{"email": {email}}.Encode(), nil)
	finish := post(t.Context(), e.svc.Passkey.FinishSignup, d.attest(t, begin), begin.Result().Cookies())
	require.Equal(t, http.StatusOK, finish.Code, finish.Body.String())
	u := e.userByEmail(t, email)
	require.NotNil(t, u, "the signup created no account")
	return u
}

func (e *testEnv) verify(t *testing.T, u *db.User) {
	t.Helper()
	require.NoError(t, e.conn.Sys().VerifyUserEmail(t.Context(), u.ID))
}

func (e *testEnv) passkeys(t *testing.T, userID string) int {
	t.Helper()
	rows, err := e.conn.Sys().ListCredentialsByType(t.Context(), &db.ListCredentialsByTypeParams{
		UserID: userID,
		Type:   string(MethodPasskey),
	})
	require.NoError(t, err)
	return len(rows)
}

func hasCookie(rec *httptest.ResponseRecorder, name string) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

// A passkey signup makes an account that cannot sign in until the email is
// confirmed. After that the passkey signs in, and neither ceremony can be
// played a second time.
func TestPasskeySignupThenLogin(t *testing.T) {
	e := newTestEnv(t)
	d := newPasskeyDevice()

	email := "new@" + testDomain()
	begin := post(t.Context(), e.svc.Passkey.BeginSignup, url.Values{"email": {email}, "name": {"New"}}.Encode(), nil)
	attestation := d.attest(t, begin)
	finish := post(t.Context(), e.svc.Passkey.FinishSignup, attestation, begin.Result().Cookies())
	require.Equal(t, http.StatusOK, finish.Code, finish.Body.String())
	assert.True(t, hasCookie(finish, signupCookieName), "the signup marks the browser")
	assert.False(t, hasCookie(finish, sessionCookieName), "a signup is not a sign-in")

	u := e.userByEmail(t, email)
	require.NotNil(t, u)
	assert.False(t, u.EmailVerified)
	assert.Equal(t, "New", u.Name)
	assert.Equal(t, 1, e.passkeys(t, u.ID))

	replay := post(t.Context(), e.svc.Passkey.FinishSignup, attestation, begin.Result().Cookies())
	assert.Equal(t, http.StatusBadRequest, replay.Code, "a finished signup ran again: %s", replay.Body.String())

	answer, cookies := d.assertion(t, e.svc)
	early := post(t.Context(), e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusForbidden, early.Code, "sign-in before the email is confirmed: %s", early.Body.String())
	assert.Zero(t, e.sessions(t, u.ID))

	e.verify(t, u)
	answer, cookies = d.assertion(t, e.svc)
	login := post(t.Context(), e.svc.Passkey.FinishLogin, answer, cookies)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	assert.True(t, hasCookie(login, sessionCookieName), "the sign-in sets a session")
	assert.Equal(t, 1, e.sessions(t, u.ID))

	replay = post(t.Context(), e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusBadRequest, replay.Code, "a captured sign-in ran again: %s", replay.Body.String())
	assert.Equal(t, 1, e.sessions(t, u.ID), "the replay opened a session")
}

// What a phishing page, another ceremony or a guessed key hands in is
// refused, and the real device still gets in afterwards.
func TestPasskeyLoginRefusesForgedAnswers(t *testing.T) {
	e := newTestEnv(t)
	d := newPasskeyDevice()
	u := d.signUp(t, e)
	e.verify(t, u)

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
		answer, cookies := device.assertion(t, e.svc)
		rec := post(t.Context(), e.svc.Passkey.FinishLogin, answer, cookies)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
	}

	answer, _ := d.assertion(t, e.svc)
	_, cookies := d.assertion(t, e.svc)
	rec := post(t.Context(), e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an answer to another ceremony: %s", rec.Body.String())

	rec = post(t.Context(), e.svc.Passkey.FinishLogin, answer, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an answer without its ceremony: %s", rec.Body.String())
	assert.Zero(t, e.sessions(t, u.ID), "a refused answer opened a session")

	answer, cookies = d.assertion(t, e.svc)
	rec = post(t.Context(), e.svc.Passkey.FinishLogin, answer, cookies)
	assert.Equal(t, http.StatusOK, rec.Code, "the real device: %s", rec.Body.String())
}

// Adding a passkey needs a session, and the ceremony belongs to the account
// that started it.
func TestPasskeyRegistrationBelongsToItsAccount(t *testing.T) {
	e := newTestEnv(t)
	d := newPasskeyDevice()
	domain := testDomain()
	alice := e.user(t, "alice@"+domain, true)
	mallory := e.user(t, "mallory@"+domain, true)

	anonymous := post(t.Context(), e.svc.Passkey.BeginRegistration, "", nil)
	assert.Equal(t, http.StatusUnauthorized, anonymous.Code, anonymous.Body.String())

	begin := post(as(t.Context(), alice.ID), e.svc.Passkey.BeginRegistration, "", nil)
	attestation := d.attest(t, begin)

	stolen := post(as(t.Context(), mallory.ID), e.svc.Passkey.FinishRegistration, attestation, begin.Result().Cookies())
	assert.Equal(
		t,
		http.StatusBadRequest,
		stolen.Code,
		"another account finished the ceremony: %s",
		stolen.Body.String(),
	)
	assert.Zero(t, e.passkeys(t, mallory.ID))

	finish := post(as(t.Context(), alice.ID), e.svc.Passkey.FinishRegistration, attestation, begin.Result().Cookies())
	require.Equal(t, http.StatusOK, finish.Code, finish.Body.String())
	assert.Equal(t, 1, e.passkeys(t, alice.ID))

	answer, cookies := d.assertion(t, e.svc)
	login := post(t.Context(), e.svc.Passkey.FinishLogin, answer, cookies)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	assert.Equal(t, 1, e.sessions(t, alice.ID))
	assert.Zero(t, e.sessions(t, mallory.ID))
}
