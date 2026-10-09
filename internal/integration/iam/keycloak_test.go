//go:build integration

package iam_test

// End-to-end SSO against a real Keycloak, started for the test.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/iam"

	"github.com/nokku-sh/nokku/internal/integration/testenv"
)

const (
	keycloakRealm     = "nokku-test"
	keycloakClientID  = "nokku-test"
	keycloakClientSec = "nokku-test-exchange"
	keycloakUsername  = "alice"
	keycloakLogin     = "hunter2-test"
)

// startKeycloak returns the issuer of a fresh test realm.
func startKeycloak(t *testing.T) string {
	t.Helper()
	base := testenv.Keycloak(t) + "/realms/" + keycloakRealm
	if err := keycloakSetupRealm(base); err != nil {
		t.Fatalf("set up keycloak realm: %v", err)
	}
	return base
}

func keycloakSetupRealm(realmBase string) error {
	root := strings.TrimSuffix(realmBase, "/realms/"+keycloakRealm)

	tokResp, err := http.PostForm(root+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {"admin"},
		"password":   {"admin"},
	})
	if err != nil {
		return err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(tokResp.Body).Decode(&tok)
	tokResp.Body.Close()
	if err != nil || tok.AccessToken == "" {
		return fmt.Errorf("keycloak admin token: %w (%s)", err, tokResp.Status)
	}
	auth := "Bearer " + tok.AccessToken

	admin := func(method, path string, body []byte) (int, error) {
		req, err := http.NewRequest(method, root+path, bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := admin(
		http.MethodPost,
		"/admin/realms",
		keycloakRealmJSON(),
	); err != nil ||
		code != http.StatusCreated {
		return fmt.Errorf("keycloak: create realm: %d %w", code, err)
	}

	return nil
}

func keycloakRealmJSON() []byte {
	mapper := func(name, userAttr, claimName string, boolean bool) map[string]any {
		cfg := map[string]any{
			"user.attribute":       userAttr,
			"id.token.claim":       "true",
			"access.token.claim":   "true",
			"userinfo.token.claim": "true",
			"claim.name":           claimName,
			"jsonType.label":       "String",
		}
		if boolean {
			cfg["jsonType.label"] = "boolean"
		}
		return map[string]any{
			"name":           name,
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-usermodel-property-mapper",
			"config":         cfg,
		}
	}

	oidcMappers := []map[string]any{
		mapper("email", "email", "email", false),
		mapper("email verified", "emailVerified", "email_verified", true),
		mapper("name", "firstName", "name", false),
		mapper("preferred username", "username", "preferred_username", false),
	}

	out, err := json.MarshalIndent(map[string]any{
		"realm":       keycloakRealm,
		"enabled":     true,
		"sslRequired": "none",
		"users": []map[string]any{{
			"username":      keycloakUsername,
			"email":         "alice@example.com",
			"firstName":     "Alice",
			"lastName":      "Example",
			"enabled":       true,
			"emailVerified": true,
			"credentials": []map[string]any{{
				"type":      "password",
				"value":     keycloakLogin,
				"temporary": false,
			}},
		}},
		"clients": []map[string]any{
			{
				"clientId":                  keycloakClientID,
				"enabled":                   true,
				"protocol":                  "openid-connect",
				"publicClient":              false,
				"secret":                    keycloakClientSec,
				"standardFlowEnabled":       true,
				"directAccessGrantsEnabled": false,
				"redirectUris":              []string{"http://nokku.test/oidc/callback"},
				"protocolMappers":           oidcMappers,
			},
		},
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	return out
}

type keycloakBrowser struct {
	c *http.Client
}

func newKeycloakBrowser() *keycloakBrowser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &keycloakBrowser{c: &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (b *keycloakBrowser) get(t *testing.T, rawURL string) (*http.Response, string) {
	t.Helper()
	resp, err := b.c.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", rawURL, err)
	}
	return resp, string(body)
}

func (b *keycloakBrowser) follow(t *testing.T, rawURL string) (*http.Response, string) {
	t.Helper()
	for range 5 {
		resp, page := b.get(t, rawURL)
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, page
		}
		next := resp.Header.Get("Location")
		if next == "" {
			t.Fatalf("redirect without Location at %s", rawURL)
		}
		rawURL = next
	}
	t.Fatalf("too many redirects starting at %s", rawURL)
	return nil, ""
}

func (b *keycloakBrowser) postForm(t *testing.T, action string, vals url.Values) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, action, strings.NewReader(vals.Encode()))
	if err != nil {
		t.Fatalf("build POST %s: %v", action, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", action, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", action, err)
	}
	return resp, string(body)
}

func loginFormAction(page string) string {
	for _, m := range reKeycloakFormAction.FindAllStringSubmatch(page, -1) {
		if strings.Contains(m[1], "login-actions") {
			return html.UnescapeString(m[1])
		}
	}
	return ""
}

var reKeycloakFormAction = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)

func keycloakAuthenticate(t *testing.T, b *keycloakBrowser, startURL string) (*http.Response, string) {
	t.Helper()
	_, page := b.follow(t, startURL)
	action := loginFormAction(page)
	if action == "" {
		t.Fatalf("keycloak returned no login form, body: %s", page)
	}
	resp, body := b.postForm(t, action, url.Values{
		"username":     {keycloakUsername},
		"password":     {keycloakLogin},
		"credentialId": {""},
		"login":        {"Sign In"},
	})
	return resp, body
}

func TestKeycloakOIDCFlow(t *testing.T) {
	base := startKeycloak(t)
	e := newTestEnv(t)
	o := e.org(t)
	e.provider(t, o.ws, iam.SSOProvider{
		ProviderID: "keycloak",
		Name:       "Keycloak",
		OIDC: iam.OIDCProvider{
			IssuerURL:       base,
			ClientID:        keycloakClientID,
			ClientSecret:    keycloakClientSec,
			JITProvisioning: true,
		},
	})
	svc := e.svc

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider=keycloak", nil)
	loginRec := httptest.NewRecorder()
	svc.OIDC.Login(loginRec, login.WithContext(anon(login.Context(), o.ws)))
	authURL := loginRec.Header().Get("Location")
	if authURL == "" {
		t.Fatalf("app login did not redirect, code=%d body=%s", loginRec.Code, loginRec.Body.String())
	}

	b := newKeycloakBrowser()
	resp, _ := keycloakAuthenticate(t, b, authURL)
	cbURL := resp.Header.Get("Location")
	if cbURL == "" {
		t.Fatalf("keycloak login did not redirect back to the app")
	}

	callback := func() *httptest.ResponseRecorder {
		cb := httptest.NewRequest(http.MethodGet, cbURL, nil)
		for _, c := range loginRec.Result().Cookies() {
			cb.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		svc.OIDC.Callback(rec, cb.WithContext(anon(cb.Context(), o.ws)))
		return rec
	}
	wantSSOSuccess(t, callback())

	u := e.userByEmail(t, o.ws, keycloakEmail)
	if u == nil {
		t.Fatal("JIT provisioned user missing after keycloak login")
	}
	if c := e.credential(t, o.ws, iam.MethodOIDC, "keycloak", ""); c != nil && c.UserID != u.ID {
		t.Error("credential linked to someone else")
	}

	// The consumed state must not survive a replay.
	wantSSOFailure(t, callback())
}

const keycloakEmail = "alice@example.com"
