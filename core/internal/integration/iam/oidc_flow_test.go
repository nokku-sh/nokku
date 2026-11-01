//go:build integration

package iam_test

// End-to-end OIDC against a small provider, so attacks can swap in an id_token.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

const (
	oidcTestSubject  = "sub-1"
	oidcClientID     = "nokku"
	oidcClientSecret = "idp-client-secret"
	oidcKeyID        = "idp"
	testProviderID   = "test"
)

type oidcIDPHarness struct {
	t      *testing.T
	key    *rsa.PrivateKey
	ts     *httptest.Server
	issuer string
	// From the last authorize. A redeemed code is empty, so it works once.
	code, challenge string
	// lastNonce goes in crafted tokens, unless they break it on purpose.
	lastNonce string
	// mint runs on the server's goroutine, so it must not touch t.
	mint  func() (string, error)
	org   org
	email string
}

type oidcFlowRun struct {
	idp         *oidcIDPHarness
	loginRec    *httptest.ResponseRecorder
	callbackURL string
}

func newOIDCIdP(t *testing.T) *oidcIDPHarness {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate idp key")

	h := &oidcIDPHarness{t: t, key: key}
	h.mint = func() (string, error) { return signIDToken(key, oidcKeyID, h.tokenClaims(nil)) }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oidc/authorize", h.authorize)
	mux.HandleFunc("POST /oidc/token", h.token)
	mux.HandleFunc("GET /oidc/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: oidcKeyID, Algorithm: string(jose.RS256), Use: "sig"},
		}})
	})
	mux.HandleFunc("GET /oidc/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                h.issuer,
			"authorization_endpoint":                h.ts.URL + "/oidc/authorize",
			"token_endpoint":                        h.ts.URL + "/oidc/token",
			"jwks_uri":                              h.ts.URL + "/oidc/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})

	h.ts = httptest.NewServer(mux)
	h.issuer = h.ts.URL + "/oidc"
	t.Cleanup(h.ts.Close)
	return h
}

// authorize signs the user straight in, like a provider that has a session.
func (h *oidcIDPHarness) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("redirect_uri") == "" || q.Get("state") == "" || q.Get("nonce") == "" ||
		q.Get("client_id") != oidcClientID || q.Get("response_type") != "code" ||
		q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" ||
		!slices.Contains(strings.Fields(q.Get("scope")), "openid") {
		http.Error(w, "invalid authorize request", http.StatusBadRequest)
		return
	}
	h.code, h.challenge = rand.Text(), q.Get("code_challenge")
	query := back.Query()
	query.Set("code", h.code)
	query.Set("state", q.Get("state"))
	back.RawQuery = query.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (h *oidcIDPHarness) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != oidcClientID || secret != oidcClientSecret {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	code := r.PostFormValue("code")
	redeemed := code != "" && code == h.code
	h.code = ""
	if !redeemed || r.PostFormValue("grant_type") != "authorization_code" ||
		oauth2.S256ChallengeFromVerifier(r.PostFormValue("code_verifier")) != h.challenge {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	idToken, err := h.mint()
	assert.NoError(h.t, err, "mint the id_token")
	writeJSON(w, map[string]any{
		"access_token": "idp-access-token",
		"token_type":   "Bearer",
		"expires_in":   600,
		"id_token":     idToken,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, v)
}

func (h *oidcIDPHarness) startOIDCFlow(t *testing.T, svc *iam.Service) *oidcFlowRun {
	t.Helper()
	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+testProviderID, nil)
	return h.startOIDCFlowFrom(t, svc, login.WithContext(anon(login.Context(), h.org.ws)))
}

// startOIDCFlowFrom takes the login request, for a signed-in user's flow.
func (h *oidcIDPHarness) startOIDCFlowFrom(t *testing.T, svc *iam.Service, login *http.Request) *oidcFlowRun {
	t.Helper()
	loginRec := httptest.NewRecorder()
	start := svc.OIDC.Login
	if login.URL.Path == "/oidc/link" {
		start = svc.OIDC.Link
	}
	start(loginRec, login)

	authorizeURL := loginRec.Header().Get("Location")
	require.NotEmpty(t, authorizeURL, "login did not redirect, code=%d body=%s", loginRec.Code, loginRec.Body.String())
	u, err := url.Parse(authorizeURL)
	require.NoError(t, err, "parse authorize redirect")
	h.lastNonce = u.Query().Get("nonce")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authorizeURL)
	require.NoError(t, err, "authorize")
	defer resp.Body.Close()
	cbURL := resp.Header.Get("Location")
	require.NotEmpty(t, cbURL, "authorize did not redirect back, code=%d", resp.StatusCode)
	return &oidcFlowRun{idp: h, loginRec: loginRec, callbackURL: cbURL}
}

func (f *oidcFlowRun) callback(t *testing.T, svc *iam.Service, extraQuery string) *httptest.ResponseRecorder {
	t.Helper()
	cbURL := f.callbackURL
	if extraQuery != "" {
		cbURL += "&" + extraQuery
	}
	cb := httptest.NewRequest(http.MethodGet, cbURL, nil)
	for _, c := range f.loginRec.Result().Cookies() {
		cb.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	svc.OIDC.Callback(rec, cb.WithContext(anon(cb.Context(), f.idp.org.ws)))
	return rec
}

func (h *oidcIDPHarness) runOIDCFlow(
	t *testing.T,
	svc *iam.Service,
	extraCallbackQuery string,
) *httptest.ResponseRecorder {
	t.Helper()
	f := h.startOIDCFlow(t, svc)
	return f.callback(t, svc, extraCallbackQuery)
}

func (h *oidcIDPHarness) setup(t *testing.T, jit bool) (*testEnv, *iam.Service) {
	t.Helper()
	return h.setupProvider(t, iam.OIDCProvider{JITProvisioning: jit})
}

func (h *oidcIDPHarness) setupProvider(t *testing.T, p iam.OIDCProvider) (*testEnv, *iam.Service) {
	t.Helper()
	return h.setupWith(t, p, iam.Deps{})
}

func (h *oidcIDPHarness) setupWith(t *testing.T, p iam.OIDCProvider, deps iam.Deps) (*testEnv, *iam.Service) {
	t.Helper()
	e := newTestEnvWith(t, deps)
	h.org = e.org(t)
	h.email = "alice@" + testDomain()
	p.IssuerURL, p.ClientID, p.ClientSecret = h.issuer, oidcClientID, oidcClientSecret
	e.provider(t, h.org.ws, iam.SSOProvider{ProviderID: testProviderID, Name: "Test OIDC", OIDC: p})
	return e, e.svc
}

func TestOIDCFlowHappyPath(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOSuccess(t, rec)

	u := e.userByEmail(t, h.org.ws, h.email)
	require.NotNil(t, u, "JIT provisioned user missing")
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, u.Role)
	assert.Equal(t, "Alice", u.Name)
	c := e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject)
	if assert.NotNil(t, c, "oidc credential not linked") {
		assert.Equal(t, u.ID, c.UserID, "oidc credential not linked")
	}
	assert.Equal(t, 1, e.sessions(t, h.org.ws, u.ID), "sessions issued")
}

func TestOIDCFlowJITDisabledRejectsUnknownIdentity(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, false)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
	assert.Nil(t, e.userByEmail(t, h.org.ws, h.email), "unknown identity was provisioned with JIT off")
}

// A provider belongs to its workspace, another's host does not know it.
func TestOIDCFlowProviderStaysInItsWorkspace(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	other := e.org(t)

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+testProviderID, nil)
	rec := httptest.NewRecorder()
	svc.OIDC.Login(rec, login.WithContext(anon(login.Context(), other.ws)))
	wantSSOFailure(t, rec)
}

func TestOIDCFlowDisabledProvider(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	p, err := svc.GetSSOProvider(anon(t.Context(), h.org.ws), testProviderID)
	require.NoError(t, err)
	p.Enabled = false
	_, err = e.svc.PutSSOProvider(anon(t.Context(), h.org.ws), *p)
	require.NoError(t, err)

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+testProviderID, nil)
	rec := httptest.NewRecorder()
	svc.OIDC.Login(rec, login.WithContext(anon(login.Context(), h.org.ws)))
	wantSSOFailure(t, rec)
}

func TestOIDCFlowStateReplay(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)

	f := h.startOIDCFlow(t, svc)
	wantSSOSuccess(t, f.callback(t, svc, ""))
	// The state is single use.
	wantSSOFailure(t, f.callback(t, svc, ""))
}

func TestOIDCFlowFlowCookieMismatch(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)

	f := h.startOIDCFlow(t, svc)
	// A callback URL relayed to a different browser.
	cb := httptest.NewRequest(http.MethodGet, f.callbackURL, nil)
	cb.AddCookie(&http.Cookie{Name: "nokku_flow", Value: "stolen"})
	cbRec := httptest.NewRecorder()
	svc.OIDC.Callback(cbRec, cb.WithContext(anon(cb.Context(), h.org.ws)))
	wantSSOFailure(t, cbRec)
}

func TestOIDCFlowIssParameterMismatch(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, "iss="+url.QueryEscape("http://evil.example/oidc")))
}

func TestOIDCFlowIDTokenExpired(t *testing.T) {
	h := newOIDCIdP(t)
	h.mintBadToken(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
}

func TestOIDCFlowIDTokenWrongIssuer(t *testing.T) {
	h := newOIDCIdP(t)
	h.mintBadToken(map[string]any{"iss": "http://evil.example/oidc"})
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
}

func TestOIDCFlowIDTokenWrongNonce(t *testing.T) {
	h := newOIDCIdP(t)
	h.mintBadToken(map[string]any{"nonce": "replayed"})
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
}

func TestOIDCFlowIDTokenWrongAudience(t *testing.T) {
	h := newOIDCIdP(t)
	h.mintBadToken(map[string]any{"aud": "another-client"})
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
}

func TestOIDCFlowIDTokenBadSignature(t *testing.T) {
	h := newOIDCIdP(t)
	// Another key but the advertised kid, so the signature check itself fails.
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate attacker key")
	h.mint = func() (string, error) {
		return signIDToken(attackerKey, oidcKeyID, h.tokenClaims(nil))
	}
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
}

// An unverified address can neither claim an account nor make one.
func TestOIDCFlowUnverifiedEmail(t *testing.T) {
	h := newOIDCIdP(t)
	h.mintBadToken(map[string]any{"email_verified": false})
	e, svc := h.setup(t, true)

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOFailure(t, rec)
	assert.Contains(t, rec.Header().Get("Location"), "email+not+verified", "want the unverified email message")
	assert.Nil(t, e.userByEmail(t, h.org.ws, h.email), "an unverified address was provisioned")
}

// Entra sends no email_verified at all. A new account takes such an address
// only when the owner trusts the provider, or whoever picks the address there
// could create the account a later invite or SCIM adopts.
func TestOIDCFlowMissingEmailVerified(t *testing.T) {
	flow := func(t *testing.T, trust bool) (*oidcIDPHarness, *testEnv, *httptest.ResponseRecorder) {
		t.Helper()
		h := newOIDCIdP(t)
		h.mintBadToken(map[string]any{"email_verified": nil})
		e, svc := h.setupProvider(t, iam.OIDCProvider{JITProvisioning: true, TrustUnverifiedEmail: trust})
		return h, e, h.runOIDCFlow(t, svc, "")
	}
	t.Run("refused", func(t *testing.T) {
		h, e, rec := flow(t, false)
		wantSSOFailure(t, rec)
		assert.Nil(t, e.userByEmail(t, h.org.ws, h.email), "an address nobody vouched for got an account")
	})
	t.Run("trusted", func(t *testing.T) {
		h, e, rec := flow(t, true)
		wantSSOSuccess(t, rec)
		assert.NotNil(t, e.userByEmail(t, h.org.ws, h.email), "a trusted provider without the claim could not sign in")
	})
}

// Without email_verified the provider does not vouch for the address, so it
// only claims an account when the owner said it may.
func TestOIDCFlowMissingEmailVerifiedLinksOnlyWhenTrusted(t *testing.T) {
	flow := func(t *testing.T, trust bool) (*oidcIDPHarness, *testEnv, *db.User, *httptest.ResponseRecorder) {
		t.Helper()
		h := newOIDCIdP(t)
		h.mintBadToken(map[string]any{"email_verified": nil})
		e, svc := h.setupProvider(t, iam.OIDCProvider{TrustUnverifiedEmail: trust})
		member := e.user(t, h.org.ws, h.email, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
		return h, e, member, h.runOIDCFlow(t, svc, "")
	}
	t.Run("refused", func(t *testing.T) {
		h, e, _, rec := flow(t, false)
		wantSSOFailure(t, rec)
		assert.Nil(t, e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject),
			"an address nobody vouched for claimed an account")
	})
	t.Run("trusted", func(t *testing.T) {
		h, e, member, rec := flow(t, true)
		wantSSOSuccess(t, rec)
		linked := e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject)
		if assert.NotNil(t, linked, "a trusted provider could not link the account") {
			assert.Equal(t, member.ID, linked.UserID, "a trusted provider could not link the account")
		}
	})
}

// A provider may give a leaver's address to someone new, with a new subject.
// That person must not land on the account.
func TestOIDCFlowRefusesASecondSubjectOnAnAccount(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	leaver := e.user(t, h.org.ws, h.email, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	e.putCredential(t, h.org.ws, db.UpsertCredentialParams{
		ID:       "old",
		UserID:   leaver.ID,
		Type:     string(iam.MethodOIDC),
		Provider: testProviderID,
		Subject:  "the-leaver",
		Data:     []byte{},
	})

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOFailure(t, rec)
	assert.Contains(t, rec.Header().Get("Location"), "identity+linked", "the reason did not reach the error page")
	assert.Nil(
		t,
		e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject),
		"a second subject landed on the account",
	)
	assert.Zero(t, e.sessions(t, h.org.ws, leaver.ID), "the new subject got a session of the old account")
}

// Whoever picks their own address at the provider must not become the owner.
func TestOIDCFlowNeverMatchesTheOwnerByEmail(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	owner := h.org.owner
	h.email = owner.Email

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOFailure(t, rec)
	assert.Contains(t, rec.Header().Get("Location"), "owner+link+required", "want the owner link message")
	assert.Nil(t, e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject),
		"the identity was linked to the owner by email")
	assert.Zero(t, e.sessions(t, h.org.ws, owner.ID), "sessions issued")

	// Signed in, the owner links it themselves.
	f := h.startOIDCFlowFrom(t, svc, linkRequest(as(t.Context(), h.org.ws, owner)))
	wantSSOSuccess(t, f.callback(t, svc, ""))
	c := e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject)
	if assert.NotNil(t, c, "no credential, want one of the owner") {
		assert.Equal(t, owner.ID, c.UserID, "credential linked to someone else")
	}
}

func (h *oidcIDPHarness) mintBadToken(override map[string]any) {
	h.mint = func() (string, error) {
		return signIDToken(h.key, oidcKeyID, h.tokenClaims(override))
	}
}

func (h *oidcIDPHarness) tokenClaims(override map[string]any) map[string]any {
	claims := map[string]any{
		"iss":            h.issuer,
		"sub":            oidcTestSubject,
		"aud":            oidcClientID,
		"nonce":          h.lastNonce,
		"email":          h.email,
		"email_verified": true,
		"name":           "Alice",
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
	maps.Copy(claims, override)
	return claims
}

func signIDToken(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		opts,
	)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(b)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// linkRequest is what the profile page's link button sends.
func linkRequest(ctx context.Context) *http.Request {
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/oidc/link?provider="+testProviderID, nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

func TestOIDCFlowLinksExistingSignedInUser(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	existing := e.user(t, h.org.ws, "bob@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)

	f := h.startOIDCFlowFrom(t, svc, linkRequest(as(t.Context(), h.org.ws, existing)))
	rec := f.callback(t, svc, "")
	wantSSOSuccess(t, rec)
	for _, c := range rec.Result().Cookies() {
		started := strings.HasSuffix(c.Name, "nokku_session") && c.Value != ""
		assert.False(t, started, "the link started a second session %s, it must keep the one that asked", c.Name)
	}

	c := e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject)
	if assert.NotNil(t, c, "no credential, want one of the existing user") {
		assert.Equal(t, existing.ID, c.UserID, "credential linked to someone else")
	}
	assert.Nil(t, e.userByEmail(t, h.org.ws, h.email), "a second account was provisioned for the linked identity")
}

func wantSSOFailure(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	loc := rec.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "/sso-error?"),
		"expected SSO error redirect, got code=%d location=%q body=%s", rec.Code, loc, rec.Body.String())
	assert.Contains(t, loc, "error=", "error redirect carries no message")
}

func wantSSOSuccess(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, "/", rec.Header().Get("Location"), "expected redirect to returnTo, code=%d body=%s",
		rec.Code, rec.Body.String())
}

// A live session alone never links. Whoever signs in at the provider gets their
// own account, not the session's.
func TestOIDCFlowPlainLoginNeverLinks(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	bob := e.user(t, h.org.ws, "bob@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+testProviderID, nil)
	f := h.startOIDCFlowFrom(t, svc, login.WithContext(as(t.Context(), h.org.ws, bob)))
	wantSSOSuccess(t, f.callback(t, svc, ""))

	c := e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject)
	require.NotNil(t, c, "no credential, want one that is not bob's")
	require.NotEqual(t, bob.ID, c.UserID, "the credential is bob's")
	assert.Zero(t, e.sessions(t, h.org.ws, bob.ID), "the provider's user got sessions as bob")
}

// A link that cannot be honored stops, it does not go on as a plain sign-in.
func TestOIDCFlowRefusedLinkStops(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)

	rec := httptest.NewRecorder()
	svc.OIDC.Link(rec, linkRequest(anon(t.Context(), h.org.ws)))
	wantSSOFailure(t, rec)
	assert.Contains(t, rec.Header().Get("Location"), "link+refused", "want the link refused message")
}
