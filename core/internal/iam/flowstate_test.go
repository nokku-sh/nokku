package iam

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nokku-sh/nokku/core/internal/cache"
)

// newSealedTestService is enough of a Service to seal flow state, with a clock the test moves.
func newSealedTestService(t *testing.T, secure bool) (*Service, *time.Time) {
	t.Helper()
	aead, err := chacha20poly1305.NewX(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return &Service{
		secure:   secure,
		flowAEAD: aead,
		spent:    cache.New[string, struct{}](10, flowStateTTL),
		now:      func() time.Time { return now },
	}, &now
}

// Only the browser that got the cookie can continue, in the same flow, while it is fresh and not after a login.
func TestSealedFlowState(t *testing.T) {
	svc, now := newSealedTestService(t, false)
	store := &sealed[authorizeState]{svc: svc, cookie: flowCookieName, use: "oidc", ttl: flowStateTTL}

	const provider = "provider-kept-out-of-sight"
	rec := httptest.NewRecorder()
	id, err := store.put(rec, authorizeState{ProviderID: provider, LinkUserID: "u1"})
	if err != nil || id == "" {
		t.Fatalf("put = %q, %v", id, err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != flowCookieName {
		t.Fatalf("cookies = %v, want the flow cookie", cookies)
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Secure {
		t.Errorf("flow cookie HttpOnly=%v SameSite=%v Secure=%v, want HttpOnly, Lax and no Secure on plain HTTP",
			cookie.HttpOnly, cookie.SameSite, cookie.Secure)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(
		cookie.Value,
	); err != nil ||
		bytes.Contains(raw, []byte(provider)) {
		t.Errorf("the state is readable in the cookie, decoding it gave %v", err)
	}

	reqWith := func(value string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
		if value != "" {
			r.AddCookie(&http.Cookie{Name: flowCookieName, Value: value})
		}
		return r
	}

	got, gotID, err := store.take(reqWith(cookie.Value))
	if err != nil || gotID != id || got.ProviderID != provider || got.LinkUserID != "u1" {
		t.Fatalf("take = %+v, %q, %v", got, gotID, err)
	}
	if _, _, err := store.take(reqWith("stolen")); err == nil {
		t.Error("a made up cookie was accepted")
	}
	if _, _, err := store.take(reqWith("")); err == nil {
		t.Error("a browser without the cookie was accepted")
	}
	tampered := cookie.Value[:len(cookie.Value)-2] + "AA"
	if _, _, err := store.take(reqWith(tampered)); err == nil {
		t.Error("a tampered cookie was accepted")
	}
	other := &sealed[authorizeState]{svc: svc, cookie: flowCookieName, use: "oauth2", ttl: flowStateTTL}
	if _, _, err := other.take(reqWith(cookie.Value)); err == nil {
		t.Error("the state of one flow opened in another")
	}

	svc.spendFlow(id)
	if _, _, err := store.take(reqWith(cookie.Value)); err == nil {
		t.Error("the state of a finished login was accepted again")
	}

	rec = httptest.NewRecorder()
	if _, err := store.put(rec, authorizeState{ProviderID: "p2"}); err != nil {
		t.Fatal(err)
	}
	fresh := rec.Result().Cookies()[0].Value
	*now = now.Add(flowStateTTL + time.Second)
	if _, _, err := store.take(reqWith(fresh)); err == nil {
		t.Error("an expired state was accepted")
	}

	if _, err := store.put(httptest.NewRecorder(), authorizeState{ReturnTo: strings.Repeat("x", 4096)}); err == nil {
		t.Error("a state too large for a cookie was set anyway")
	}
}

// A GET that adds a way in is taken only from the app itself, so a link on another site cannot end a session.
func TestRequireFreshRefusesForeignGets(t *testing.T) {
	var svc Service
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("the route ran") })
	for _, site := range []string{"same-site", "cross-site", "none", ""} {
		r := httptest.NewRequest(http.MethodGet, "/oidc/link", nil)
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		rec := httptest.NewRecorder()
		svc.RequireFresh(next).ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
			t.Errorf("Sec-Fetch-Site %q: code %d, cookies %v, want 403 and the session left alone",
				site, rec.Code, rec.Result().Cookies())
		}
	}
}

func TestSafeReturnTo(t *testing.T) {
	for _, ok := range []string{"/", "/secrets/42?tab=audit", "/a/b#c"} {
		if got := safeReturnTo(ok); got != ok {
			t.Errorf("safeReturnTo(%q) = %q, want it kept", ok, got)
		}
	}
	for _, bad := range []string{
		"", "https://evil.example", "//evil.example", "/\\evil.example",
		"/\t/evil.example", "/\n/evil.example", "/\r/evil.example", "/\x00x", "/" + strings.Repeat("x", maxReturnTo),
	} {
		if got := safeReturnTo(bad); got != "" {
			t.Errorf("safeReturnTo(%q) = %q, want it dropped", bad, got)
		}
	}
}
