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

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
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
		Email:         oidcTestEmail,
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

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider=ws1", nil)
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

// seedOIDCIdP wires the store to the harness: a ws1 provider row pointing
// at the mock issuer with the mock client credentials.
func seedOIDCIdP(h *oidcIDPHarness, conn *fakeStoreConn) {
	seedOIDCProvider(conn, &OIDCProvider{
		IssuerURL:       h.issuer,
		ClientID:        h.m.ClientID,
		ClientSecret:    h.m.ClientSecret,
		JITProvisioning: true,
	})
}

// providerConfigJSON rebuilds the stored config blob for a test that needs
// a variant of the seeded provider.
func providerConfigJSON(t *testing.T, oidc *OIDCProvider) []byte {
	t.Helper()
	b, err := json.Marshal(providerConfig{OIDC: oidc})
	if err != nil {
		t.Fatalf("marshal provider config: %v", err)
	}
	return b
}

func TestOIDCFlowHappyPath(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	svc := newSSOTestService(t, store, conn)

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOSuccess(t, rec)

	hasSession := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Error("callback issued no session cookie")
	}

	u := store.byEmail[oidcTestEmail]
	if u == nil {
		t.Fatal("JIT provisioned user missing")
	}
	if !u.EmailVerified {
		t.Error("JIT user email should inherit provider-verified status")
	}
	if c := store.creds[string(MethodOIDC)+"|ws1|sub-1"]; c == nil {
		t.Error("oidc credential not linked")
	}
	if len(store.sessions) != 1 {
		t.Errorf("sessions issued = %d, want 1", len(store.sessions))
	}
}

func TestOIDCFlowJITDisabledRejectsUnknownIdentity(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	conn.provider.Config = crypto.EncryptedBytes(providerConfigJSON(t, &OIDCProvider{
		IssuerURL:       h.issuer,
		ClientID:        h.m.ClientID,
		ClientSecret:    h.m.ClientSecret,
		JITProvisioning: false,
	}))
	svc := newSSOTestService(t, store, conn)

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOFailure(t, rec)
	if store.byEmail[oidcTestEmail] != nil {
		t.Error("unknown identity was provisioned with JIT off")
	}
}

func TestOIDCFlowStateReplay(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	svc := newSSOTestService(t, store, conn)

	f := h.startOIDCFlow(t, svc)
	rec := f.callback(t, svc, "")
	wantSSOSuccess(t, rec)

	// The same callback URL carries the consumed state; replaying it (the
	// classic relay-attack shape) must fail. The flow cookie is fresh, so
	// only the single-use state stops this.
	replay := f.callback(t, svc, "")
	wantSSOFailure(t, replay)
}

func TestOIDCFlowFlowCookieMismatch(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	svc := newSSOTestService(t, store, conn)

	f := h.startOIDCFlow(t, svc)

	// The callback arrives without the flow cookie the login browser got:
	// a callback URL relayed to a different browser.
	cb := httptest.NewRequest(http.MethodGet, f.callbackUR, nil)
	cb.AddCookie(&http.Cookie{Name: "nokku_flow", Value: "stolen"})
	cbRec := httptest.NewRecorder()
	svc.OIDC.Callback(cbRec, cb)
	wantSSOFailure(t, cbRec)
}

func TestOIDCFlowIssParameterMismatch(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	svc := newSSOTestService(t, store, conn)

	rec := h.runOIDCFlow(t, svc, "iss="+url.QueryEscape("http://evil.example/oidc"))
	wantSSOFailure(t, rec)
}

// The next three tests mint a structurally valid id_token with one broken
// claim or the wrong key, swapping it into the token response.

func TestOIDCFlowIDTokenWrongNonce(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	h.mintBadToken(t, map[string]any{"nonce": "replayed"})
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	svc := newSSOTestService(t, store, conn)

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOFailure(t, rec)
}

func TestOIDCFlowIDTokenWrongAudience(t *testing.T) {
	h := newOIDCIdP(t)
	h.user()
	h.mintBadToken(t, map[string]any{"aud": "another-client"})
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	svc := newSSOTestService(t, store, conn)

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOFailure(t, rec)
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
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	svc := newSSOTestService(t, store, conn)

	rec := h.runOIDCFlow(t, svc, "")
	wantSSOFailure(t, rec)
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
const (
	oidcTestSubject = "sub-1"
	oidcTestEmail   = "alice@example.com"
)

// tokenClaims builds a full claim set; overrides patch individual claims.
func (h *oidcIDPHarness) tokenClaims(t *testing.T, override map[string]any) map[string]any {
	t.Helper()
	claims := map[string]any{
		"iss":            h.issuer,
		"sub":            oidcTestSubject,
		"aud":            h.m.ClientID,
		"nonce":          h.lastNonce,
		"email":          oidcTestEmail,
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
	// account: LinkUserID rides the login state into the callback.
	h := newOIDCIdP(t)
	h.user()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCIdP(h, conn)
	svc := newSSOTestService(t, store, conn)

	existing, err := store.CreateUser(t.Context(), &db.CreateUserParams{
		Email: oidcTestEmail,
		Name:  "Alice Local",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{
		ID:   existing.ID,
		Kind: actor.KindUser,
	})
	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider=ws1", nil).WithContext(ctx)
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

	if c := store.creds[string(MethodOIDC)+"|ws1|sub-1"]; c == nil || c.UserID != existing.ID {
		t.Errorf("credential linked to %v, want existing user %s", c, existing.ID)
	}
	if u := store.byEmail[oidcTestEmail]; u == nil || u.ID != existing.ID {
		t.Error("existing user was not reused for the linked identity")
	}
}

// wantSSOFailure asserts the redirect to the SSO error page.
func wantSSOFailure(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://nokku.test/sso-error?") {
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
