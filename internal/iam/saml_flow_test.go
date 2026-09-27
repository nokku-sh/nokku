package iam

// The SAML SP-initiated flow, exercised end to end against an in-process
// crewjam saml.IdentityProvider that serves real metadata and signs real
// assertions. Attack paths tamper with the signing key, replay the
// RelayState, and relay responses across flows.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// samlIDPHarness is the in-process IdP. Metadata always advertises the trusted
// keypair; assertions are signed with the signing keypair, which a test can
// rotate to simulate a forged signer while the SP still trusts the old key.
type samlIDPHarness struct {
	ts *httptest.Server

	trustedKey  *rsa.PrivateKey
	trustedCert *x509.Certificate

	signingKey  *rsa.PrivateKey
	signingCert *x509.Certificate

	session *saml.Session

	// spMetadata is the SP's EntityDescriptor, set by the test after the
	// service under test is built.
	spMetadata *saml.EntityDescriptor

	org   org
	email string
	// down makes the metadata endpoint fail.
	down bool
}

func newSAMLIdP(t *testing.T) *samlIDPHarness {
	t.Helper()
	h := &samlIDPHarness{}
	h.resetKeys(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metadata", func(w http.ResponseWriter, _ *http.Request) {
		if h.down {
			http.Error(w, "maintenance", http.StatusServiceUnavailable)
			return
		}
		// Metadata always advertises the trusted keypair, so a rotated
		// signing key is a genuine forgery from the SP's point of view.
		metadataURL, _ := url.Parse(h.ts.URL + "/metadata")
		ssoURL, _ := url.Parse(h.ts.URL + "/sso")
		metaIdp := &saml.IdentityProvider{
			Key:         h.trustedKey,
			Certificate: h.trustedCert,
			MetadataURL: *metadataURL,
			SSOURL:      *ssoURL,
		}
		buf, err := xml.MarshalIndent(metaIdp.Metadata(), "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(buf)
	})
	mux.HandleFunc("GET /sso", func(w http.ResponseWriter, r *http.Request) {
		h.identityProvider().ServeSSO(w, r)
	})

	ts := httptest.NewServer(mux)
	h.ts = ts
	t.Cleanup(ts.Close)
	return h
}

// resetKeys generates a fresh trusted and signing keypair.
func (h *samlIDPHarness) resetKeys(t *testing.T) {
	t.Helper()
	trustedKey, trustedCert := newKeyCert(t)
	h.trustedKey, h.trustedCert = trustedKey, trustedCert
	h.signingKey, h.signingCert = trustedKey, trustedCert
}

// forge rotates the signing keypair away from the trusted one: metadata
// still advertises the trusted certificate, so an assertion signed now
// must fail verification at the SP.
func (h *samlIDPHarness) forge(t *testing.T) {
	t.Helper()
	h.signingKey, h.signingCert = newKeyCert(t)
}

func (h *samlIDPHarness) identityProvider() *saml.IdentityProvider {
	metadataURL, _ := url.Parse(h.ts.URL + "/metadata")
	ssoURL, _ := url.Parse(h.ts.URL + "/sso")
	return &saml.IdentityProvider{
		Key:                     h.signingKey,
		Certificate:             h.signingCert,
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
		ServiceProviderProvider: h,
		SessionProvider:         h,
	}
}

// GetServiceProvider implements saml.ServiceProviderProvider.
func (h *samlIDPHarness) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if h.spMetadata == nil || id != h.spMetadata.EntityID {
		return nil, os.ErrNotExist
	}
	return h.spMetadata, nil
}

// GetSession implements saml.SessionProvider.
func (h *samlIDPHarness) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	return h.session
}

// setup builds the service and an enterprise org whose SAML provider points
// at the harness, with alice queued as the IdP user.
func (h *samlIDPHarness) setup(t *testing.T) (*testEnv, *Service) {
	t.Helper()
	e := newTestEnv(t)
	h.org = e.org(t)
	e.provider(t, h.org, SSOProvider{
		Method: MethodSAML,
		Name:   "Test SAML",
		SAML:   &SAMLIDP{MetadataURL: h.ts.URL + "/metadata", JITProvisioning: true},
	})
	h.spMetadata = spMetadataFor(t, e.svc)
	h.alice("alice@" + h.org.domain)
	return e, e.svc
}

func (h *samlIDPHarness) alice(email string) {
	h.email = email
	now := time.Now()
	h.session = &saml.Session{
		ID:             "saml-session-1",
		CreateTime:     now,
		ExpireTime:     now.Add(time.Hour),
		Index:          "index-1",
		NameID:         email,
		NameIDFormat:   string(saml.EmailAddressNameIDFormat),
		UserName:       "alice",
		UserEmail:      email,
		UserCommonName: "Alice Example",
		UserGivenName:  "Alice",
		UserSurname:    "Example",
	}
}

func newKeyCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, cert
}

// samlFlowRun is one started flow: the login response's cookies plus the
// signed response the IdP posted back.
type samlFlowRun struct {
	loginCookies []*http.Cookie
	samlResponse string
	relayState   string
}

var (
	reSAMLResponse = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	reRelayState   = regexp.MustCompile(`name="RelayState" value="([^"]+)"`)
)

// startSAMLFlow runs the SP login and the IdP authorize leg, ending with
// the browser holding the auto-POST form for the ACS.
func (h *samlIDPHarness) startSAMLFlow(t *testing.T, svc *Service) *samlFlowRun {
	t.Helper()

	login := httptest.NewRequest(http.MethodGet, "/saml/login?provider="+h.org.ws, nil)
	loginRec := httptest.NewRecorder()
	svc.SAML.Login(loginRec, login)
	redirect := loginRec.Header().Get("Location")
	if redirect == "" {
		t.Fatalf("saml login did not redirect, code=%d body=%s", loginRec.Code, loginRec.Body.String())
	}

	resp, err := http.Get(redirect)
	if err != nil {
		t.Fatalf("idp sso: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read idp sso body: %v", err)
	}
	page := string(body)

	m := reSAMLResponse.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("idp returned no SAMLResponse form, body=%s", page)
	}
	samlResponse := html.UnescapeString(m[1])
	rs := reRelayState.FindStringSubmatch(page)
	if rs == nil {
		t.Fatalf("idp returned no RelayState form, body=%s", page)
	}

	return &samlFlowRun{
		loginCookies: loginRec.Result().Cookies(),
		samlResponse: samlResponse,
		relayState:   rs[1],
	}
}

// postACS submits the flow's response to the ACS endpoint.
func (f *samlFlowRun) postACS(
	t *testing.T,
	svc *Service,
	relayState string,
	withCookies bool,
) *httptest.ResponseRecorder {
	t.Helper()
	return f.postACSCustom(t, svc, relayState, f.cookiesFor(withCookies))
}

// postACSCustom submits the flow's response with explicit cookies.
func (f *samlFlowRun) postACSCustom(
	t *testing.T,
	svc *Service,
	relayState string,
	cookies []*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"SAMLResponse": {f.samlResponse}, "RelayState": {relayState}}
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	svc.SAML.Callback(rec, req)
	return rec
}

func (f *samlFlowRun) cookiesFor(with bool) []*http.Cookie {
	if !with {
		return nil
	}
	return f.loginCookies
}

// spMetadataFor captures the SP metadata the service under test serves.
func spMetadataFor(t *testing.T, svc *Service) *saml.EntityDescriptor {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	rec := httptest.NewRecorder()
	svc.SAML.Metadata(rec, req)

	ed := &saml.EntityDescriptor{}
	if err := xml.Unmarshal(rec.Body.Bytes(), ed); err != nil {
		t.Fatalf("parse served SP metadata: %v", err)
	}
	return ed
}

func TestSAMLFlowHappyPath(t *testing.T) {
	h := newSAMLIdP(t)
	e, svc := h.setup(t)

	f := h.startSAMLFlow(t, svc)
	wantSSOSuccess(t, f.postACS(t, svc, f.relayState, true))

	u := e.userByEmail(t, h.email)
	if u == nil {
		t.Fatal("JIT provisioned user missing")
	}
	if !u.EmailVerified {
		t.Error("SAML assertion email should be treated as verified")
	}
	if u.Name != "Alice Example" {
		t.Errorf("user name = %q, want value from the cn attribute", u.Name)
	}
	if c := e.credential(t, MethodSAML, h.org.ws, h.email); c == nil || c.UserID != u.ID {
		t.Error("saml credential not linked")
	}
	if n := e.sessions(t, u.ID); n != 1 {
		t.Errorf("sessions issued = %d, want 1", n)
	}
}

// A workspace that lost its domain loses the accounts under it, including
// identities it linked before.
func TestSAMLFlowLostDomainRejectsLinkedIdentity(t *testing.T) {
	h := newSAMLIdP(t)
	e, svc := h.setup(t)
	f := h.startSAMLFlow(t, svc)
	wantSSOSuccess(t, f.postACS(t, svc, f.relayState, true))

	e.dropDomain(t, h.org.ws, h.org.domain)
	f = h.startSAMLFlow(t, svc)
	wantSSOFailure(t, f.postACS(t, svc, f.relayState, true))
}

// ageMetadata backdates the SP's cached copy of the IdP metadata.
func ageMetadata(svc *Service, by time.Duration) {
	svc.SAML.mu.Lock()
	defer svc.SAML.mu.Unlock()
	for k, m := range svc.SAML.metas {
		m.at = m.at.Add(-by)
		svc.SAML.metas[k] = m
	}
}

// An IdP that rotates its signing key without any overlap keeps working:
// the failed verification refetches the metadata and tries again.
func TestSAMLFlowFollowsIdPKeyRotation(t *testing.T) {
	h := newSAMLIdP(t)
	_, svc := h.setup(t)
	f := h.startSAMLFlow(t, svc)
	wantSSOSuccess(t, f.postACS(t, svc, f.relayState, true))

	h.resetKeys(t)
	// Still within the cache lifetime, so the first verification runs
	// against the old key, but past the one-minute refetch throttle.
	ageMetadata(svc, 2*time.Minute)
	f = h.startSAMLFlow(t, svc)
	wantSSOSuccess(t, f.postACS(t, svc, f.relayState, true))
}

// An IdP metadata outage does not lock anyone out.
func TestSAMLFlowSurvivesMetadataOutage(t *testing.T) {
	h := newSAMLIdP(t)
	_, svc := h.setup(t)
	f := h.startSAMLFlow(t, svc)
	wantSSOSuccess(t, f.postACS(t, svc, f.relayState, true))

	h.down = true
	ageMetadata(svc, time.Hour)
	f = h.startSAMLFlow(t, svc)
	wantSSOSuccess(t, f.postACS(t, svc, f.relayState, true))
}

func TestSAMLSPCertificateNeverExpires(t *testing.T) {
	e := newTestEnv(t)
	if got := e.svc.SAML.spCert.NotAfter.Year(); got != 9999 {
		t.Errorf("SP certificate expires in %d", got)
	}
}

func TestSAMLFlowForgedSignature(t *testing.T) {
	h := newSAMLIdP(t)
	e, svc := h.setup(t)
	// The IdP now signs with a key the SP's trusted metadata does not carry.
	h.forge(t)

	f := h.startSAMLFlow(t, svc)
	wantSSOFailure(t, f.postACS(t, svc, f.relayState, true))
	if e.userByEmail(t, h.email) != nil {
		t.Error("a forged assertion provisioned an account")
	}
}

func TestSAMLFlowRelayStateReplay(t *testing.T) {
	h := newSAMLIdP(t)
	_, svc := h.setup(t)

	f := h.startSAMLFlow(t, svc)
	wantSSOSuccess(t, f.postACS(t, svc, f.relayState, true))
	// RelayState is single use.
	wantSSOFailure(t, f.postACS(t, svc, f.relayState, true))
}

func TestSAMLFlowCrossFlowResponse(t *testing.T) {
	h := newSAMLIdP(t)
	e, svc := h.setup(t)

	// A response minted for flow 1 relayed into flow 2's browser session is
	// stopped by InResponseTo: it answers flow 1's request.
	f1 := h.startSAMLFlow(t, svc)
	f2 := h.startSAMLFlow(t, svc)
	wantSSOFailure(t, f1.postACSCustom(t, svc, f2.relayState, f2.loginCookies))
	if e.userByEmail(t, h.email) != nil {
		t.Error("a cross-flow response provisioned an account")
	}
}

func TestSAMLFlowFlowCookieMismatch(t *testing.T) {
	h := newSAMLIdP(t)
	_, svc := h.setup(t)

	f := h.startSAMLFlow(t, svc)
	wantSSOFailure(t, f.postACS(t, svc, f.relayState, false))
}

func TestSAMLIdentityMapping(t *testing.T) {
	assertion := func(nameID string, attrs ...saml.Attribute) *saml.Assertion {
		a := &saml.Assertion{}
		if nameID != "" {
			a.Subject = &saml.Subject{NameID: &saml.NameID{Value: nameID}}
		}
		a.AttributeStatements = []saml.AttributeStatement{{Attributes: attrs}}
		return a
	}
	attr := func(name, friendly, value string) saml.Attribute {
		return saml.Attribute{
			Name: name, FriendlyName: friendly,
			Values: []saml.AttributeValue{{Value: value}},
		}
	}

	opts := identity(assertion("alice@example.com",
		attr("urn:oid:0.9.2342.19200300.100.1.3", "mail", "alice@example.com"),
		attr("urn:oid:2.5.4.3", "cn", "Alice Example"),
	))
	if opts.Subject != "alice@example.com" || opts.Email != "alice@example.com" ||
		opts.Name != "Alice Example" {
		t.Errorf("identity mapping by NameID+mail+cn = %+v", opts)
	}

	// Keycloak-style OID mail attribute and givenName/surname split.
	opts = identity(assertion("a1b2c3",
		attr("urn:oid:1.2.840.113549.1.9.1", "emailaddress", "bob@corp.example"),
		attr("urn:oid:2.5.4.42", "givenName", "Bob"),
		attr("urn:oid:2.5.4.4", "sn", "Barnes"),
	))
	if opts.Subject != "a1b2c3" || opts.Email != "bob@corp.example" ||
		opts.Name != "Bob Barnes" {
		t.Errorf("identity mapping by OID attributes = %+v", opts)
	}

	// No NameID: the email becomes the stable linking subject.
	opts = identity(assertion("",
		attr("mail", "", "carol@corp.example"),
	))
	if opts.Subject != "carol@corp.example" {
		t.Errorf("missing NameID should fall back to email, got %+v", opts)
	}
}
