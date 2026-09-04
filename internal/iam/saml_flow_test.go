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
}

func newSAMLIdP(t *testing.T) *samlIDPHarness {
	t.Helper()
	h := &samlIDPHarness{}
	h.resetKeys(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metadata", func(w http.ResponseWriter, _ *http.Request) {
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

func (h *samlIDPHarness) alice() {
	now := time.Now()
	h.session = &saml.Session{
		ID:             "saml-session-1",
		CreateTime:     now,
		ExpireTime:     now.Add(time.Hour),
		Index:          "index-1",
		NameID:         "alice@example.com",
		NameIDFormat:   string(saml.EmailAddressNameIDFormat),
		UserName:       "alice",
		UserEmail:      "alice@example.com",
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

	login := httptest.NewRequest(http.MethodGet, "/saml/login?provider=ws1", nil)
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
	h.alice()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedSAMLProvider(conn, &SAMLIDP{
		MetadataURL:     h.ts.URL + "/metadata",
		JITProvisioning: true,
	})
	svc := newSSOTestService(t, store, conn)
	h.spMetadata = spMetadataFor(t, svc)

	f := h.startSAMLFlow(t, svc)
	rec := f.postACS(t, svc, f.relayState, true)
	wantSSOSuccess(t, rec)

	u := store.byEmail["alice@example.com"]
	if u == nil {
		t.Fatal("JIT provisioned user missing")
	}
	if !u.EmailVerified {
		t.Error("SAML assertion email should be treated as verified")
	}
	if u.Name != "Alice Example" {
		t.Errorf("user name = %q, want value from the cn attribute", u.Name)
	}
	if c := store.creds[string(MethodSAML)+"|ws1|alice@example.com"]; c == nil {
		t.Error("saml credential not linked")
	}
	if len(store.sessions) != 1 {
		t.Errorf("sessions issued = %d, want 1", len(store.sessions))
	}
}

func TestSAMLFlowForgedSignature(t *testing.T) {
	h := newSAMLIdP(t)
	h.alice()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedSAMLProvider(conn, &SAMLIDP{
		MetadataURL:     h.ts.URL + "/metadata",
		JITProvisioning: true,
	})
	svc := newSSOTestService(t, store, conn)
	h.spMetadata = spMetadataFor(t, svc)

	// The IdP now signs with a key the SP's trusted metadata does not carry.
	h.forge(t)

	f := h.startSAMLFlow(t, svc)
	rec := f.postACS(t, svc, f.relayState, true)
	wantSSOFailure(t, rec)
	if len(store.sessions) != 0 {
		t.Error("a forged assertion issued a session")
	}
}

func TestSAMLFlowRelayStateReplay(t *testing.T) {
	h := newSAMLIdP(t)
	h.alice()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedSAMLProvider(conn, &SAMLIDP{
		MetadataURL:     h.ts.URL + "/metadata",
		JITProvisioning: true,
	})
	svc := newSSOTestService(t, store, conn)
	h.spMetadata = spMetadataFor(t, svc)

	f := h.startSAMLFlow(t, svc)
	rec := f.postACS(t, svc, f.relayState, true)
	wantSSOSuccess(t, rec)

	// The same signed response and RelayState posted again must be
	// rejected: RelayState is single use.
	replay := f.postACS(t, svc, f.relayState, true)
	wantSSOFailure(t, replay)
}

func TestSAMLFlowCrossFlowResponse(t *testing.T) {
	h := newSAMLIdP(t)
	h.alice()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedSAMLProvider(conn, &SAMLIDP{
		MetadataURL:     h.ts.URL + "/metadata",
		JITProvisioning: true,
	})
	svc := newSSOTestService(t, store, conn)
	h.spMetadata = spMetadataFor(t, svc)

	// Start two flows. A response minted for flow 1 relayed into flow 2's
	// in-flight browser session (flow 2's RelayState and flow cookie) is
	// stopped by the InResponseTo check: the response answers flow 1's
	// request, not flow 2's.
	f1 := h.startSAMLFlow(t, svc)
	f2 := h.startSAMLFlow(t, svc)

	rec := f1.postACSCustom(t, svc, f2.relayState, f2.loginCookies)
	wantSSOFailure(t, rec)
	if len(store.sessions) != 0 {
		t.Error("a cross-flow response issued a session")
	}
}

func TestSAMLFlowFlowCookieMismatch(t *testing.T) {
	h := newSAMLIdP(t)
	h.alice()
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedSAMLProvider(conn, &SAMLIDP{
		MetadataURL:     h.ts.URL + "/metadata",
		JITProvisioning: true,
	})
	svc := newSSOTestService(t, store, conn)
	h.spMetadata = spMetadataFor(t, svc)

	f := h.startSAMLFlow(t, svc)
	rec := f.postACS(t, svc, f.relayState, false)
	wantSSOFailure(t, rec)
}

func TestSAMLIdentityMapping(t *testing.T) {
	h := newSAMLIdP(t)
	store, conn := newFakeStore(), &fakeStoreConn{}
	seedSAMLProvider(conn, &SAMLIDP{MetadataURL: h.ts.URL + "/metadata"})
	svc := newSSOTestService(t, store, conn)
	cfg := &SAMLIDP{JITProvisioning: true}

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

	opts := svc.SAML.identity(cfg, assertion("alice@example.com",
		attr("urn:oid:0.9.2342.19200300.100.1.3", "mail", "alice@example.com"),
		attr("urn:oid:2.5.4.3", "cn", "Alice Example"),
	))
	if opts.Subject != "alice@example.com" || opts.Email != "alice@example.com" ||
		opts.Name != "Alice Example" {
		t.Errorf("identity mapping by NameID+mail+cn = %+v", opts)
	}

	// Keycloak-style OID mail attribute and givenName/surname split.
	opts = svc.SAML.identity(cfg, assertion("a1b2c3",
		attr("urn:oid:1.2.840.113549.1.9.1", "emailaddress", "bob@corp.example"),
		attr("urn:oid:2.5.4.42", "givenName", "Bob"),
		attr("urn:oid:2.5.4.4", "sn", "Barnes"),
	))
	if opts.Subject != "a1b2c3" || opts.Email != "bob@corp.example" ||
		opts.Name != "Bob Barnes" {
		t.Errorf("identity mapping by OID attributes = %+v", opts)
	}

	// No NameID: the email becomes the stable linking subject.
	opts = svc.SAML.identity(cfg, assertion("",
		attr("mail", "", "carol@corp.example"),
	))
	if opts.Subject != "carol@corp.example" {
		t.Errorf("missing NameID should fall back to email, got %+v", opts)
	}
}
