package iam

// End-to-end SSO flows against a real Keycloak in a Docker container. This
// is the tier above the in-process mocks: a genuine IdP with its own
// discovery document, JWKS, login pages, and SAML response signing. The
// container starts once per test binary and is reaped when the process
// exits; tests skip when Docker is unavailable.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
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

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	keycloakRealm     = "nokku-test"
	keycloakImage     = "quay.io/keycloak/keycloak:26.3"
	keycloakClientID  = "nokku-test"
	keycloakClientSec = "nokku-test-exchange"
	keycloakUsername  = "alice"
	keycloakLogin     = "hunter2-test"
)

// keycloakOnce starts the container exactly once per test binary.
var keycloakOnce struct {
	once sync.Once
	base string // http://host:port/realms/nokku-test
	ctr  testcontainers.Container
	// noDocker marks "environment cannot run Docker" (skip, not fail).
	noDocker bool
	err      error
}

// startKeycloak returns the realm base URL, starting the container on
// first use.
func startKeycloak(t *testing.T) string {
	t.Helper()
	keycloakOnce.once.Do(func() {
		if !dockerAvailable() {
			keycloakOnce.noDocker = true
			return
		}
		keycloakOnce.base, keycloakOnce.ctr, keycloakOnce.err = startKeycloakContainer()
	})
	if keycloakOnce.noDocker {
		t.Skip("docker not available, skipping keycloak integration tests")
	}
	if keycloakOnce.err != nil {
		t.Fatalf("start keycloak: %v", keycloakOnce.err)
	}
	return keycloakOnce.base
}

// dockerAvailable reports whether a Docker endpoint is likely reachable.
func dockerAvailable() bool {
	if os.Getenv("DOCKER_HOST") != "" {
		return true
	}
	_, err := os.Stat("/var/run/docker.sock")
	return err == nil
}

func startKeycloakContainer() (string, testcontainers.Container, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	realm, err := os.CreateTemp("", "nokku-keycloak-realm-*.json")
	if err != nil {
		return "", nil, err
	}
	defer os.Remove(realm.Name())
	if _, err := realm.Write(keycloakRealmJSON()); err != nil {
		return "", nil, err
	}
	if err := realm.Close(); err != nil {
		return "", nil, err
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started:      true,
		Image:        keycloakImage,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
			"KC_HOSTNAME_STRICT":          "false",
		},
		Cmd: []string{"start-dev", "--import-realm"},
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      realm.Name(),
			ContainerFilePath: "/opt/keycloak/data/import/realm.json",
			FileMode:          0o644,
		}},
		WaitingFor: wait.ForHTTP("/realms/" + keycloakRealm + "/.well-known/openid-configuration").
			WithPort("8080/tcp").
			WithStatusCodeMatcher(func(code int) bool { return code == http.StatusOK }).
			WithStartupTimeout(3 * time.Minute),
	})
	if err != nil {
		return "", nil, err
	}
	// The container is intentionally left running: the testcontainers
	// reaper tears it down when the test binary exits.

	host, err := ctr.Host(ctx)
	if err != nil {
		return "", ctr, err
	}
	port, err := ctr.MappedPort(ctx, "8080/tcp")
	if err != nil {
		return "", ctr, err
	}
	base := "http://" + net.JoinHostPort(host, port.Port()) + "/realms/" + keycloakRealm

	// Keycloak's realm import drops redirectUris on SAML clients, and the
	// SAML login validation needs them (the ACS is otherwise rejected with
	// invalid_redirect_uri). Patch the client through the admin API once.
	if err := keycloakAllowAcs(base); err != nil {
		return "", ctr, err
	}
	return base, ctr, nil
}

// keycloakAllowAcs sets the SAML client's valid redirect URIs to the ACS.
func keycloakAllowAcs(realmBase string) error {
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

// keycloakRealmJSON builds the realm import: one user, an OIDC client for
// the code flow, and a SAML client whose entityID matches the SP metadata
// the service under test serves. Redirect targets under nokku.test are
// never connected to; the test browser stops at the 302.
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

// keycloakBrowser is a test browser: a cookie jar, no redirect following,
// and helpers that return the final body for form parsing.
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

// follow GETs until a non-redirect response, so tests can be agnostic
// about how many hops Keycloak inserts before the login page.
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

// loginFormAction finds the login form action on a Keycloak login page.
func loginFormAction(page string) string {
	for _, m := range reKeycloakFormAction.FindAllStringSubmatch(page, -1) {
		if strings.Contains(m[1], "login-actions") {
			return html.UnescapeString(m[1])
		}
	}
	return ""
}

var reKeycloakFormAction = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)

// keycloakAuthenticate follows the flow's redirect into Keycloak, authenticates
// alice, and returns the response that carries the browser back to the
// SP: a 302 Location for OIDC callbacks, or the SAML auto-POST page.
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
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedOIDCProvider(conn, &OIDCProvider{
		IssuerURL:       base,
		ClientID:        keycloakClientID,
		ClientSecret:    keycloakClientSec,
		JITProvisioning: true,
	})
	svc := newSSOTestService(t, store, conn)

	// Start the flow at the app, then authenticate at the real IdP.
	login := httptest.NewRequest(http.MethodGet, "/oidc/login?provider=ws1", nil)
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

	u := store.byEmail["alice@example.com"]
	if u == nil {
		t.Fatal("JIT provisioned user missing after keycloak login")
	}
	if !u.EmailVerified {
		t.Error("email_verified claim from keycloak not honored")
	}
	if !hasCredentialFor(store, string(MethodOIDC), "ws1", u.ID) {
		t.Errorf("oidc credential not linked, creds: %v", store.creds)
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

// hasCredentialFor reports whether the store links user to provider.
func hasCredentialFor(store *fakeStore, method, provider, userID string) bool {
	for _, c := range store.creds {
		if c.Type == method && c.Provider == provider && c.UserID == userID {
			return true
		}
	}
	return false
}

func TestKeycloakSAMLFlow(t *testing.T) {
	base := startKeycloak(t)
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedSAMLProvider(conn, &SAMLIDP{
		MetadataURL:     base + "/protocol/saml/descriptor",
		JITProvisioning: true,
	})
	svc := newSSOTestService(t, store, conn)

	login := httptest.NewRequest(http.MethodGet, "/saml/login?provider=ws1", nil)
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

	u := store.byEmail["alice@example.com"]
	if u == nil {
		t.Fatal("JIT provisioned user missing after keycloak saml login")
	}
	if u.Name != "Alice Example" {
		t.Errorf("user name = %q, want given+sn from the keycloak assertion", u.Name)
	}
	// Keycloak sends the username as NameID (crewjam requests the
	// transient policy and Keycloak answers with the username), so the
	// linking subject is "alice" here. Email, name, and verification all
	// come from the signed attributes.
	if c := store.creds[string(MethodSAML)+"|ws1|alice"]; c == nil || c.UserID != u.ID {
		t.Errorf("saml credential not linked to the provisioned user, creds: %v", store.creds)
	}
}
