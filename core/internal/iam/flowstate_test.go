package iam

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nokku-sh/nokku/core/internal/cache"
)

// Only the cookie's browser continues, in the same flow, once, while fresh.
func TestSealedFlowState(t *testing.T) {
	aead, err := chacha20poly1305.NewX(make([]byte, chacha20poly1305.KeySize))
	require.NoError(t, err)
	now := time.Now()
	svc := &Service{
		flowAEAD: aead,
		spent:    cache.New[string, struct{}](10, flowStateTTL),
		now:      func() time.Time { return now },
	}
	store := &sealed[authorizeState]{svc: svc, cookie: flowCookieName, use: "oidc", ttl: flowStateTTL}

	const provider = "provider-kept-out-of-sight"
	rec := httptest.NewRecorder()
	id, err := store.put(rec, authorizeState{ProviderID: provider, LinkUserID: "u1"})
	require.NoError(t, err)
	require.NotEmpty(t, id)
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	cookie := cookies[0]
	require.Equal(t, flowCookieName, cookie.Name)
	assert.True(t, cookie.HttpOnly, "the flow cookie must be HttpOnly")
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.False(t, cookie.Secure, "no Secure on plain HTTP")
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if assert.NoError(t, err, "the cookie is not base64") {
		assert.NotContains(t, string(raw), provider, "the state is readable in the cookie")
	}

	reqWith := func(value string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
		if value != "" {
			r.AddCookie(&http.Cookie{Name: flowCookieName, Value: value})
		}
		return r
	}

	got, gotID, err := store.take(reqWith(cookie.Value))
	require.NoError(t, err)
	require.Equal(t, id, gotID)
	require.Equal(t, provider, got.ProviderID)
	require.Equal(t, "u1", got.LinkUserID)

	refused := func(s *sealed[authorizeState], value, why string) {
		t.Helper()
		_, _, err := s.take(reqWith(value))
		assert.Error(t, err, why)
	}
	refused(store, "stolen", "a made up cookie was accepted")
	refused(store, "", "a browser without the cookie was accepted")
	tampered := cookie.Value[:len(cookie.Value)-2] + "AA"
	refused(store, tampered, "a tampered cookie was accepted")
	other := &sealed[authorizeState]{svc: svc, cookie: flowCookieName, use: "oauth2", ttl: flowStateTTL}
	refused(other, cookie.Value, "the state of one flow opened in another")

	svc.spendFlow(id)
	refused(store, cookie.Value, "the state of a finished login was accepted again")

	rec = httptest.NewRecorder()
	_, err = store.put(rec, authorizeState{ProviderID: "p2"})
	require.NoError(t, err)
	fresh := rec.Result().Cookies()[0].Value
	now = now.Add(flowStateTTL + time.Second)
	refused(store, fresh, "an expired state was accepted")

	_, err = store.put(httptest.NewRecorder(), authorizeState{ReturnTo: strings.Repeat("x", 4096)})
	assert.Error(t, err, "a state too large for a cookie was set anyway")
}

// A GET that adds a way in must come from the app, not a link on another site.
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
		assert.Equal(t, http.StatusForbidden, rec.Code, "Sec-Fetch-Site %q", site)
		assert.Empty(t, rec.Result().Cookies(), "Sec-Fetch-Site %q: the session must be left alone", site)
	}
}

func TestSafeReturnTo(t *testing.T) {
	for _, ok := range []string{"/", "/secrets/42?tab=audit", "/a/b#c"} {
		assert.Equal(t, ok, safeReturnTo(ok))
	}
	for _, bad := range []string{
		"", "https://evil.example", "//evil.example", "/\\evil.example",
		"/\t/evil.example", "/\n/evil.example", "/\r/evil.example", "/\x00x", "/" + strings.Repeat("x", maxReturnTo),
	} {
		assert.Empty(t, safeReturnTo(bad), "safeReturnTo(%q) must drop it", bad)
	}
}
