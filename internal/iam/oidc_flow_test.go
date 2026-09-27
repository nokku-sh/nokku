package iam

// The OIDC authorization-code flow, exercised end to end against an
// in-process mock IdP (oauth2-proxy/mockoidc) with a hand-served discovery
// document so the tests can swap the token endpoint's id_token for a
// crafted one on the attack paths.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/oauth2-proxy/mockoidc"
)

// oidcIDPHarness hosts mockoidc's endpoints behind a test server. The server is
// not mockoidc's own: discovery is hand-rolled so every endpoint URL points
// here, and the token endpoint is wrapped so a test can replace the
// returned id_token (attack paths). mockoidc's Server.Addr is pointed at
// this server before anything is minted, so iss claims carry this URL.
type oidcIDPHarness struct {
	m      *mockoidc.MockOIDC
	ts     *httptest.Server
	issuer string
	// lastNonce is the nonce the flow under test sent to the authorize
	// endpoint; crafted tokens must carry it unless they break nonce on
	// purpose.
	lastNonce string
	// mint returns a replacement id_token for the next token call, or nil.
	mint func() string
	// org owns the provider, email is the IdP user's address under its
	// verified domain.
	org   org
	email string
}

func newOIDCIdP(t *testing.T) *oidcIDPHarness {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate idp key: %v", err)
	}
	m, err := mockoidc.NewServer(key)
	if err != nil {
		t.Fatalf("build mockoidc: %v", err)
	}

	h := &oidcIDPHarness{m: m}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oidc/authorize", m.Authorize)
	mux.HandleFunc("POST /oidc/token", h.token)
	mux.HandleFunc("GET /oidc/userinfo", m.Userinfo)
	mux.HandleFunc("GET /oidc/jwks", m.JWKS)
	mux.HandleFunc("GET /oidc/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                h.issuer,
			"authorization_endpoint":                h.ts.URL + "/oidc/authorize",
			"token_endpoint":                        h.ts.URL + "/oidc/token",
			"userinfo_endpoint":                     h.ts.URL + "/oidc/userinfo",
			"jwks_uri":                              h.ts.URL + "/oidc/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})

	// Point mockoidc's address bookkeeping at the test server before its
	// first token mint, so iss claims and discovery agree. mockoidc never
	// serves anything itself here; only Addr() is read.
	ts := httptest.NewServer(mux)
	m.Server = &http.Server{Addr: strings.TrimPrefix(ts.URL, "http://")}
	h.ts = ts
	h.issuer = ts.URL + "/oidc"

	t.Cleanup(ts.Close)
	return h
}

// token wraps mockoidc's token endpoint, optionally swapping the id_token.
func (h *oidcIDPHarness) token(w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	h.m.Token(rec, r)
	for k, vs := range rec.Header() {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	body := rec.Body.Bytes()
	if h.mint != nil && rec.Code == http.StatusOK {
		var tr struct {
			IDToken string `json:"id_token"`
		}
		if json.Unmarshal(body, &tr) == nil && tr.IDToken != "" {
			tr.IDToken = h.mint()
			body, _ = json.Marshal(tr)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(body)
}

// user queues the IdP user the next authorize call authenticates.
func (h *oidcIDPHarness) user() {
	h.m.QueueUser(&mockoidc.MockUser{
		Subject:       oidcTestSubject,
		Email:         h.email,
		EmailVerified: true,
	})
}

// noRedirectClient follows exactly zero redirects.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// oidcFlowRun is one full flow, kept around so the replay test can re-post
// callback.
type oidcFlowRun struct {
	idp        *oidcIDPHarness
	loginRec   *httptest.ResponseRecorder
	callbackUR string
}

// startOIDCFlow runs the login and authorize legs and returns the flow.
func (h *oidcIDPHarness) startOIDCFlow(t *testing.T, svc *Service) *oidcFlowRun {
	t.Helper()

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+h.org.ws, nil)
	loginRec := httptest.NewRecorder()
	svc.OIDC.Login(loginRec, login)

	authorizeURL := loginRec.Header().Get("Location")
	if authorizeURL == "" {
		t.Fatalf("login did not redirect, code=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	h.lastNonce = u.Query().Get("nonce")

	// The authorize leg: one request, no redirect following.
	resp, err := noRedirectClient().Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	cbURL := resp.Header.Get("Location")
	if cbURL == "" {
		t.Fatalf("authorize did not redirect back, code=%d", resp.StatusCode)
	}
	return &oidcFlowRun{idp: h, loginRec: loginRec, callbackUR: cbURL}
}

// callback completes the flow; extraQuery is appended to the callback URL
// verbatim (iss parameter tests). cookies carries the login-set cookies.
func (f *oidcFlowRun) callback(t *testing.T, svc *Service, extraQuery string) *httptest.ResponseRecorder {
	t.Helper()
	cbURL := f.callbackUR
	if extraQuery != "" {
		cbURL += "&" + extraQuery
	}
	cb := httptest.NewRequest(http.MethodGet, cbURL, nil)
	for _, c := range f.loginRec.Result().Cookies() {
		cb.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	svc.OIDC.Callback(rec, cb)
	return rec
}

// runOIDCFlow drives one full flow end to end and returns the callback
// response.
func (h *oidcIDPHarness) runOIDCFlow(
	t *testing.T,
	svc *Service,
	extraCallbackQuery string,
) *httptest.ResponseRecorder {
	t.Helper()
	f := h.startOIDCFlow(t, svc)
	return f.callback(t, svc, extraCallbackQuery)
}

// setup builds the service and an enterprise org whose OIDC provider points
// at the harness.
func (h *oidcIDPHarness) setup(t *testing.T, jit bool) (*testEnv, *Service) {
	t.Helper()
	e := newTestEnv(t)
	h.org = e.org(t)
	h.email = "alice@" + h.org.domain
	e.provider(t, h.org, SSOProvider{
		Method: MethodOIDC,
		Name:   "Test OIDC",
		OIDC: &OIDCProvider{
			IssuerURL:       h.issuer,
			ClientID:        h.m.ClientID,
			ClientSecret:    h.m.ClientSecret,
			JITProvisioning: jit,
		},
	})
	return e, e.svc
}

func TestOIDCFlowHappyPath(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	h.user()

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOSuccess(t, rec)

	u := e.userByEmail(t, h.email)
	if u == nil {
		t.Fatal("JIT provisioned user missing")
	}
	if !u.EmailVerified {
		t.Error("JIT user under a verified domain should be verified")
	}
	if c := e.credential(t, MethodOIDC, h.org.ws, oidcTestSubject); c == nil || c.UserID != u.ID {
		t.Error("oidc credential not linked")
	}
	if !e.isMember(t, h.org.ws, u.ID) {
		t.Error("user did not join the provider's workspace")
	}
	if n := e.sessions(t, u.ID); n != 1 {
		t.Errorf("sessions issued = %d, want 1", n)
	}
}

func TestOIDCFlowJITDisabledRejectsUnknownIdentity(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, false)
	h.user()

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
	if e.userByEmail(t, h.email) != nil {
		t.Error("unknown identity was provisioned with JIT off")
	}
}

// An enterprise IdP asserting an address outside its workspace's verified
// domains must not reach that account, even when the IdP calls it verified.
func TestOIDCFlowRejectsForeignDomain(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	victim := e.user(t, "ceo@"+testDomain(), true)
	h.email = victim.Email
	h.user()

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
	if e.credential(t, MethodOIDC, h.org.ws, oidcTestSubject) != nil {
		t.Error("foreign identity was linked")
	}
	if n := e.sessions(t, victim.ID); n != 0 {
		t.Errorf("victim got %d sessions", n)
	}
}

func TestOIDCFlowDisabledProvider(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	p, err := svc.GetSSOProvider(t.Context(), h.org.ws)
	if err != nil {
		t.Fatal(err)
	}
	p.Enabled = false
	if err := putSSOProvider(t.Context(), e.conn.Sys(), *p); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	svc.OIDC.Login(rec, httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+h.org.ws, nil))
	wantSSOFailure(t, rec)
}

func TestOIDCFlowWrongMethodProvider(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)

	rec := httptest.NewRecorder()
	svc.OAuth2.Login(rec, httptest.NewRequest(http.MethodGet, "/oauth/login?provider="+h.org.ws, nil))
	wantSSOFailure(t, rec)
}

func TestOIDCFlowStateReplay(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)
	h.user()

	f := h.startOIDCFlow(t, svc)
	wantSSOSuccess(t, f.callback(t, svc, ""))
	// The state is single use, a replayed callback fails.
	wantSSOFailure(t, f.callback(t, svc, ""))
}

func TestOIDCFlowFlowCookieMismatch(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)
	h.user()

	f := h.startOIDCFlow(t, svc)
	// A callback URL relayed to a different browser.
	cb := httptest.NewRequest(http.MethodGet, f.callbackUR, nil)
	cb.AddCookie(&http.Cookie{Name: "nokku_flow", Value: "stolen"})
	cbRec := httptest.NewRecorder()
	svc.OIDC.Callback(cbRec, cb)
	wantSSOFailure(t, cbRec)
}

func TestOIDCFlowIssParameterMismatch(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)
	h.user()

	wantSSOFailure(t, h.runOIDCFlow(t, svc, "iss="+url.QueryEscape("http://evil.example/oidc")))
}

// The next three tests mint a structurally valid id_token with one broken
// claim or the wrong key, swapping it into the token response.

func TestOIDCFlowIDTokenWrongNonce(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	h.mintBadToken(t, map[string]any{"nonce": "replayed"})
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
}

func TestOIDCFlowIDTokenWrongAudience(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	h.mintBadToken(t, map[string]any{"aud": "another-client"})
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
}

func TestOIDCFlowIDTokenBadSignature(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	// Sign with a key that is not the one JWKS advertises, keeping the kid
	// the IdP advertises so the failure is the signature check itself.
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	h.mint = func() string {
		kid, _ := h.m.Keypair.KeyID()
		return signIDToken(t, attackerKey, kid, h.tokenClaims(t, nil))
	}
	_, svc := h.setup(t, true)

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
}

// mintBadToken swaps in a correctly signed token (the IdP key, matching
// kid) with overrides merged over the expected claims.
func (h *oidcIDPHarness) mintBadToken(t *testing.T, override map[string]any) {
	t.Helper()
	h.mint = func() string {
		kid, err := h.m.Keypair.KeyID()
		if err != nil {
			t.Fatalf("key id: %v", err)
		}
		return signIDToken(t, h.m.Keypair.PrivateKey, kid, h.tokenClaims(t, override))
	}
}

// oidcTestSubject is the subject every mock IdP user carries.
const oidcTestSubject = "sub-1"

// tokenClaims builds a full claim set; overrides patch individual claims.
func (h *oidcIDPHarness) tokenClaims(t *testing.T, override map[string]any) map[string]any {
	t.Helper()
	claims := map[string]any{
		"iss":            h.issuer,
		"sub":            oidcTestSubject,
		"aud":            h.m.ClientID,
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

func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
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
		t.Fatalf("build signer: %v", err)
	}
	obj, err := signer.Sign(b)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}
	return s
}

func TestOIDCFlowLinksExistingSignedInUser(t *testing.T) {
	// A signed-in user who starts the flow links the identity to their
	// account.
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	existing := e.user(t, "bob@"+h.org.domain, true)
	h.user()

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+h.org.ws, nil).
		WithContext(as(t.Context(), existing.ID))
	loginRec := httptest.NewRecorder()
	svc.OIDC.Login(loginRec, login)

	resp, err := noRedirectClient().Get(loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()

	cb := httptest.NewRequest(http.MethodGet, resp.Header.Get("Location"), nil)
	for _, c := range loginRec.Result().Cookies() {
		cb.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()
	svc.OIDC.Callback(cbRec, cb)
	wantSSOSuccess(t, cbRec)

	if c := e.credential(t, MethodOIDC, h.org.ws, oidcTestSubject); c == nil || c.UserID != existing.ID {
		t.Errorf("credential linked to %v, want existing user %s", c, existing.ID)
	}
	if e.userByEmail(t, h.email) != nil {
		t.Error("a second account was provisioned for the linked identity")
	}
}

// wantSSOFailure asserts the redirect to the SSO error page.
func wantSSOFailure(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/sso-error?") {
		t.Fatalf("expected SSO error redirect, got code=%d location=%q body=%s",
			rec.Code, loc, rec.Body.String())
	}
	if !strings.Contains(loc, "error=") {
		t.Errorf("error redirect carries no message: %q", loc)
	}
}

// wantSSOSuccess asserts the default successful callback redirect.
func wantSSOSuccess(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("expected redirect to returnTo, got code=%d location=%q body=%s",
			rec.Code, got, rec.Body.String())
	}
}
