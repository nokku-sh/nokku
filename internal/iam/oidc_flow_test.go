package iam

// End-to-end OIDC tests against mockoidc. Discovery is hand-served so attack
// paths can swap the token endpoint's id_token for a crafted one.

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

type oidcIDPHarness struct {
	m      *mockoidc.MockOIDC
	ts     *httptest.Server
	issuer string
	// lastNonce must be carried by crafted tokens unless they break it on purpose.
	lastNonce string
	mint      func() string
	org       org
	email     string
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

	// Set before the first mint so iss claims and discovery agree.
	ts := httptest.NewServer(mux)
	m.Server = &http.Server{Addr: strings.TrimPrefix(ts.URL, "http://")}
	h.ts = ts
	h.issuer = ts.URL + "/oidc"

	t.Cleanup(ts.Close)
	return h
}

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

func (h *oidcIDPHarness) user() {
	h.m.QueueUser(&mockoidc.MockUser{
		Subject:       oidcTestSubject,
		Email:         h.email,
		EmailVerified: true,
	})
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

type oidcFlowRun struct {
	idp        *oidcIDPHarness
	loginRec   *httptest.ResponseRecorder
	callbackUR string
}

func (h *oidcIDPHarness) startOIDCFlow(t *testing.T, svc *Service) *oidcFlowRun {
	t.Helper()

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+testProviderID, nil)
	loginRec := httptest.NewRecorder()
	svc.OIDC.Login(loginRec, login.WithContext(anon(login.Context(), h.org.ws)))

	authorizeURL := loginRec.Header().Get("Location")
	if authorizeURL == "" {
		t.Fatalf("login did not redirect, code=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	h.lastNonce = u.Query().Get("nonce")

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
	svc.OIDC.Callback(rec, cb.WithContext(anon(cb.Context(), f.idp.org.ws)))
	return rec
}

func (h *oidcIDPHarness) runOIDCFlow(
	t *testing.T,
	svc *Service,
	extraCallbackQuery string,
) *httptest.ResponseRecorder {
	t.Helper()
	f := h.startOIDCFlow(t, svc)
	return f.callback(t, svc, extraCallbackQuery)
}

func (h *oidcIDPHarness) setup(t *testing.T, jit bool) (*testEnv, *Service) {
	t.Helper()
	e := newTestEnv(t)
	h.org = e.org(t)
	h.email = "alice@" + testDomain()
	e.provider(t, h.org.ws, SSOProvider{
		ProviderID: testProviderID,
		Name:       "Test OIDC",
		OIDC: OIDCProvider{
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

	u := e.userByEmail(t, h.org.ws, h.email)
	if u == nil {
		t.Fatal("JIT provisioned user missing")
	}
	if u.Role != "member" || u.Name != "" && u.Name != "Alice" {
		t.Errorf("JIT user = %+v", u)
	}
	if c := e.credential(t, h.org.ws, MethodOIDC, testProviderID, oidcTestSubject); c == nil || c.UserID != u.ID {
		t.Error("oidc credential not linked")
	}
	if n := e.sessions(t, h.org.ws, u.ID); n != 1 {
		t.Errorf("sessions issued = %d, want 1", n)
	}
}

func TestOIDCFlowJITDisabledRejectsUnknownIdentity(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, false)
	h.user()

	wantSSOFailure(t, h.runOIDCFlow(t, svc, ""))
	if e.userByEmail(t, h.org.ws, h.email) != nil {
		t.Error("unknown identity was provisioned with JIT off")
	}
}

// A provider belongs to its workspace, another workspace's host does not
// know it.
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
	if err != nil {
		t.Fatal(err)
	}
	p.Enabled = false
	if _, err := putSSOProvider(t.Context(), e.conn.Sys(), h.org.ws.ID, *p); err != nil {
		t.Fatal(err)
	}

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+testProviderID, nil)
	rec := httptest.NewRecorder()
	svc.OIDC.Login(rec, login.WithContext(anon(login.Context(), h.org.ws)))
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
	svc.OIDC.Callback(cbRec, cb.WithContext(anon(cb.Context(), h.org.ws)))
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

const (
	oidcTestSubject = "sub-1"
	testProviderID  = "test"
)

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
	existing := e.user(t, h.org.ws, "bob@"+testDomain(), "member")
	h.user()

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+testProviderID, nil).
		WithContext(as(t.Context(), h.org.ws, existing))
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
	svc.OIDC.Callback(cbRec, cb.WithContext(anon(cb.Context(), h.org.ws)))
	wantSSOSuccess(t, cbRec)

	if c := e.credential(
		t,
		h.org.ws,
		MethodOIDC,
		testProviderID,
		oidcTestSubject,
	); c == nil ||
		c.UserID != existing.ID {
		t.Errorf("credential linked to %v, want existing user %s", c, existing.ID)
	}
	if e.userByEmail(t, h.org.ws, h.email) != nil {
		t.Error("a second account was provisioned for the linked identity")
	}
}

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

func wantSSOSuccess(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("expected redirect to returnTo, got code=%d location=%q body=%s",
			rec.Code, got, rec.Body.String())
	}
}
