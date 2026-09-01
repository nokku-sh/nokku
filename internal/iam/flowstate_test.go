package iam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFlowBinding covers the login CSRF flow cookie: it is set at flow
// start, required (matching) at callback, and its SAML None variant carries
// Secure, since the IdP posts back cross-site.
func TestFlowBinding(t *testing.T) {
	rec := httptest.NewRecorder()
	value := startFlowBinding(rec, false)
	if value == "" {
		t.Fatal("startFlowBinding returned no value")
	}

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == flowCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("flow cookie not set")
	}
	if !cookie.HttpOnly {
		t.Error("flow cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Secure {
		t.Error("GET-callback flows must not set Secure on a non-HTTPS binding")
	}

	reqWith := func(cookieValue string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
		if cookieValue != "" {
			r.AddCookie(&http.Cookie{Name: flowCookieName, Value: cookieValue})
		}
		return r
	}

	if !checkFlowBinding(reqWith(value), value) {
		t.Error("matching flow cookie was rejected")
	}
	if checkFlowBinding(reqWith("wrong"), value) {
		t.Error("mismatched flow cookie was accepted")
	}
	if checkFlowBinding(reqWith(""), value) {
		t.Error("missing flow cookie was accepted")
	}
	if !checkFlowBinding(reqWith(value), "") {
		t.Error("flow without a recorded binding must be allowed")
	}

	// SAML: cross-site IdP form POST needs a None cookie, which requires
	// Secure.
	rec2 := httptest.NewRecorder()
	if startFlowBinding(rec2, true) == "" {
		t.Fatal("startFlowBinding returned no value")
	}
	var samlCookie *http.Cookie
	for _, c := range rec2.Result().Cookies() {
		if c.Name == flowCookieName {
			samlCookie = c
		}
	}
	if samlCookie == nil {
		t.Fatal("saml flow cookie not set")
	}
	if samlCookie.SameSite != http.SameSiteNoneMode || !samlCookie.Secure {
		t.Errorf("saml cookie SameSite=%v Secure=%v, want None+Secure",
			samlCookie.SameSite, samlCookie.Secure)
	}
}

// TestLinkUserIDFor checks the forced-linking guard: a signed-in user
// starting an SSO login from a cross-site navigation must not enter linking
// mode, same-origin and header-less (older) clients must.
func TestLinkUserIDFor(t *testing.T) {
	const uid = "01a05a0f-d857-723f-a3ed-c43125834aa5"
	ctx := ContextWithPrincipal(context.Background(), Principal{ID: uid, Kind: KindUser})

	tests := []struct {
		name    string
		site    string
		wantUID string
	}{
		{"same origin navigation", "same-origin", uid},
		{"direct navigation", "none", uid},
		{"no fetch metadata (older browser)", "", uid},
		{"cross-site navigation", "cross-site", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/oidc/login", nil)
			if test.site != "" {
				r.Header.Set("Sec-Fetch-Site", test.site)
			}
			if got := linkUserIDFor(ctx, r); got != test.wantUID {
				t.Errorf("linkUserIDFor = %q, want %q", got, test.wantUID)
			}
		})
	}
}
