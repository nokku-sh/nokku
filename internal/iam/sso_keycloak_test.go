package iam

// End-to-end SSO tests against the Keycloak from compose.test.yml. The test
// realm is created once per test binary, and tests skip when no Keycloak
// answers.

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
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	keycloakRoot      = "http://localhost:8080"
	keycloakRealm     = "nokku-test"
	keycloakClientID  = "nokku-test"
	keycloakClientSec = "nokku-test-exchange"
	keycloakUsername  = "alice"
	keycloakLogin     = "hunter2-test"
)

var keycloakOnce struct {
	once sync.Once
	skip bool
	err  error
}

func startKeycloak(t *testing.T) string {
	t.Helper()
	base := keycloakRoot + "/realms/" + keycloakRealm
	keycloakOnce.once.Do(func() {
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(keycloakRoot + "/realms/master")
		if err != nil {
			keycloakOnce.skip = true
			return
		}
		resp.Body.Close()
		keycloakOnce.err = keycloakSetupRealm(base)
	})
	if keycloakOnce.skip {
		if os.Getenv("CI") != "" {
			t.Fatal("no test Keycloak in CI")
		}
		t.Skip("no test Keycloak, start it with compose.test.yml")
	}
	if keycloakOnce.err != nil {
		t.Fatalf("set up keycloak realm: %v", keycloakOnce.err)
	}
	return base
}

// keycloakSetupRealm creates the test realm from scratch, the compose
// Keycloak outlives the tests.
func keycloakSetupRealm(realmBase string) error {
	root := strings.TrimSuffix(realmBase, "/realms/"+keycloakRealm)
	clientID := "http://nokku.test/saml/metadata"

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
	if _, err := admin(http.MethodDelete, "/admin/realms/"+keycloakRealm, nil); err != nil {
		return err
	}
	if code, err := admin(
		http.MethodPost,
		"/admin/realms",
		keycloakRealmJSON(),
	); err != nil ||
		code != http.StatusCreated {
		return fmt.Errorf("keycloak: create realm: %d %w", code, err)
	}

	// Keycloak drops redirectUris on imported SAML clients, which the ACS
	// needs. Patch them in.
	req, err := http.NewRequest(http.MethodGet,
		root+"/admin/realms/"+keycloakRealm+"/clients?clientId="+url.QueryEscape(clientID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	var clients []map[string]any
	err = json.NewDecoder(resp.Body).Decode(&clients)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if len(clients) != 1 {
		return fmt.Errorf("keycloak: expected 1 saml client, got %d", len(clients))
	}
	id, _ := clients[0]["id"].(string)
	clients[0]["redirectUris"] = []string{"http://nokku.test/saml/acs"}

	body, err := json.Marshal(clients[0])
	if err != nil {
		return err
	}
	put, err := http.NewRequest(http.MethodPut,
		root+"/admin/realms/"+keycloakRealm+"/clients/"+id, bytes.NewReader(body))
	if err != nil {
		return err
	}
	put.Header.Set("Authorization", auth)
	put.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(put)
	if err != nil {
		return err
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("keycloak: update saml client: %s", putResp.Status)
	}
	return nil
}

func keycloakRealmJSON() []byte {
	mapper := func(name, protocol, mapper, userAttr, claimName, friendly string, boolean bool) map[string]any {
		cfg := map[string]any{
			"user.attribute":       userAttr,
			"id.token.claim":       "true",
			"access.token.claim":   "true",
			"userinfo.token.claim": "true",
		}
		if protocol == "openid-connect" {
			cfg["claim.name"] = claimName
			cfg["jsonType.label"] = "boolean"
			if !boolean {
				cfg["jsonType.label"] = "String"
			}
		} else {
			cfg["attribute.name"] = claimName
			cfg["attribute.nameformat"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
			cfg["friendly.name"] = friendly
		}
		return map[string]any{
			"name":           name,
			"protocol":       protocol,
			"protocolMapper": mapper,
			"config":         cfg,
		}
	}

	oidcMappers := []map[string]any{
		mapper("email", "openid-connect", "oidc-usermodel-property-mapper", "email", "email", "", false),
		mapper("email verified", "openid-connect",
			"oidc-usermodel-property-mapper", "emailVerified", "email_verified", "", true),
		mapper("name", "openid-connect", "oidc-usermodel-property-mapper", "firstName", "name", "", false),
		mapper("preferred username", "openid-connect",
			"oidc-usermodel-property-mapper", "username", "preferred_username", "", false),
	}
	samlMappers := []map[string]any{
		mapper("email", "saml", "saml-user-property-mapper", "email", "urn:oid:1.2.840.113549.1.9.1", "email", false),
		mapper("given name", "saml", "saml-user-property-mapper", "firstName", "urn:oid:2.5.4.42", "givenName", false),
		mapper("surname", "saml", "saml-user-property-mapper", "lastName", "urn:oid:2.5.4.4", "sn", false),
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
			{
				"clientId":         "http://nokku.test/saml/metadata",
				"enabled":          true,
				"protocol":         "saml",
				"fullScopeAllowed": true,
				"attributes": map[string]string{
					"saml.client.signature":            "false",
					"saml_assertion_signature":         "true",
					"saml.server.signature":            "true",
					"saml.signature.algorithm":         "RSA_SHA256",
					"saml_assertion_consumer_url_post": "http://nokku.test/saml/acs",
					"saml.force.post.binding":          "false",
					"saml.encrypt":                     "false",
					"saml_name_id_format":              "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
					"saml_force_name_id_format":        "true",
				},
				"protocolMappers": samlMappers,
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
	e, o := keycloakOrg(t)
	e.provider(t, o, SSOProvider{
		Method: MethodOIDC,
		OIDC: &OIDCProvider{
			IssuerURL:       base,
			ClientID:        keycloakClientID,
			ClientSecret:    keycloakClientSec,
			JITProvisioning: true,
		},
	})
	svc := e.svc

	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider="+o.ws, nil)
	loginRec := httptest.NewRecorder()
	svc.OIDC.Login(loginRec, login)
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

	cb := httptest.NewRequest(http.MethodGet, cbURL, nil)
	for _, c := range loginRec.Result().Cookies() {
		cb.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()
	svc.OIDC.Callback(cbRec, cb)
	wantSSOSuccess(t, cbRec)

	u := e.userByEmail(t, keycloakEmail)
	if u == nil {
		t.Fatal("JIT provisioned user missing after keycloak login")
	}
	if !u.EmailVerified {
		t.Error("email_verified claim from keycloak not honored")
	}

	// The consumed state must not survive a replay.
	replay := httptest.NewRequest(http.MethodGet, cbURL, nil)
	for _, c := range loginRec.Result().Cookies() {
		replay.AddCookie(c)
	}
	replayRec := httptest.NewRecorder()
	svc.OIDC.Callback(replayRec, replay)
	wantSSOFailure(t, replayRec)
}

const keycloakEmail = "alice@example.com"

func keycloakOrg(t *testing.T) (*testEnv, org) {
	t.Helper()
	e := newTestEnv(t)
	o := e.org(t)
	e.claimDomain(t, o.ws, "example.com")
	return e, o
}

func TestKeycloakSAMLFlow(t *testing.T) {
	base := startKeycloak(t)
	e, o := keycloakOrg(t)
	e.provider(t, o, SSOProvider{
		Method: MethodSAML,
		SAML:   &SAMLIDP{MetadataURL: base + "/protocol/saml/descriptor", JITProvisioning: true},
	})
	svc := e.svc

	login := httptest.NewRequest(http.MethodGet, "/saml/login?provider="+o.ws, nil)
	loginRec := httptest.NewRecorder()
	svc.SAML.Login(loginRec, login)
	redirect := loginRec.Header().Get("Location")
	if redirect == "" {
		t.Fatalf("saml login did not redirect, code=%d body=%s", loginRec.Code, loginRec.Body.String())
	}

	b := newKeycloakBrowser()
	resp, page := keycloakAuthenticate(t, b, redirect)

	// The response after login should be the auto-POST form for the ACS;
	// tolerate one intermediate redirect before it.
	m := reSAMLResponse.FindStringSubmatch(page)
	if m == nil {
		if next := resp.Header.Get("Location"); next != "" {
			_, page = b.follow(t, next)
			m = reSAMLResponse.FindStringSubmatch(page)
		}
	}
	if m == nil {
		t.Fatalf("keycloak returned no SAMLResponse form, body: %s", page)
	}
	rs := reRelayState.FindStringSubmatch(page)
	if rs == nil {
		t.Fatalf("keycloak returned no RelayState form, body: %s", page)
	}

	f := &samlFlowRun{
		loginCookies: loginRec.Result().Cookies(),
		samlResponse: html.UnescapeString(m[1]),
		relayState:   rs[1],
	}
	rec := f.postACS(t, svc, f.relayState, true)
	wantSSOSuccess(t, rec)

	u := e.userByEmail(t, keycloakEmail)
	if u == nil {
		t.Fatal("JIT provisioned user missing after keycloak saml login")
	}
	// Keycloak sends the username as NameID, so the subject is "alice".
	if c := e.credential(t, MethodSAML, o.ws, "alice"); c == nil || c.UserID != u.ID {
		t.Error("saml credential not linked to the provisioned user")
	}
}
