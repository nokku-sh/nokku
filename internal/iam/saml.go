package iam

// The SAML SP-initiated flow. The SP keypair is generated once and stored
// in the saml_keypair table, encrypted at rest.

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

// samlState is the cross-request payload carried in the RelayState.
type samlState struct {
	ProviderID string `json:"provider_id"`
	RequestID  string `json:"request_id"`
	ReturnTo   string `json:"return_to,omitempty"`
	LinkUserID string `json:"link_user_id,omitempty"`
	FlowCookie string `json:"flow_cookie"`
}

// samlFlow serves the SAML SP-initiated flow. One SP keypair serves every
// provider.
type samlFlow struct {
	svc     *Service
	linker  *linker
	state   *state[samlState]
	spKey   *rsa.PrivateKey
	spCert  *x509.Certificate
	certPEM []byte

	mu    sync.Mutex
	metas map[string]fetchedMetadata // by metadata URL
}

type fetchedMetadata struct {
	ed *saml.EntityDescriptor
	at time.Time
}

// newSAMLFlow loads the SP keypair, generating it on first boot. The stored
// pair wins, so concurrent first boots converge on one key.
func newSAMLFlow(ctx context.Context, svc *Service) (*samlFlow, error) {
	keyPEM, certPEM, err := svc.samlKeypair(ctx)
	if err != nil {
		return nil, err
	}
	key, cert, err := parseSAMLKeypair(keyPEM, certPEM)
	if err != nil {
		return nil, err
	}
	return &samlFlow{
		svc:     svc,
		linker:  &linker{svc: svc, credType: MethodSAML},
		state:   newState[samlState](svc.cache, "saml:state:", flowStateTTL),
		spKey:   key,
		spCert:  cert,
		certPEM: certPEM,
		metas:   map[string]fetchedMetadata{},
	}, nil
}

// Login starts the SP-initiated flow for the "provider" query parameter.
func (h *samlFlow) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.svc.loginProvider(ctx, r.URL.Query().Get("provider"), MethodSAML)
	if err != nil {
		fail(w, r, "provider not configured")
		return
	}
	sp, err := h.serviceProvider(ctx, cfg.SAML, false)
	if err != nil {
		slog.Warn("saml login: provider metadata invalid", "error", err, "provider", cfg.ProviderID)
		fail(w, r, "provider metadata invalid")
		return
	}
	ssoURL := cmp.Or(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), sp.GetSSOBindingLocation(saml.HTTPPostBinding))
	if ssoURL == "" {
		fail(w, r, "no SSO endpoint in metadata")
		return
	}
	req, err := sp.MakeAuthenticationRequest(ssoURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		fail(w, r, "request creation failed")
		return
	}
	// The IdP posts the assertion back cross-site, so the binding cookie
	// must be SameSite=None, which only works over HTTPS.
	flowCookie, err := startFlowBinding(w, h.svc.secure)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	relayState, err := h.state.Put(ctx, samlState{
		ProviderID: cfg.ProviderID,
		RequestID:  req.ID,
		ReturnTo:   safeReturnTo(r.URL.Query().Get("return_to")),
		LinkUserID: linkUserIDFor(ctx, r),
		FlowCookie: flowCookie,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	redirect, err := req.Redirect(relayState, sp)
	if err != nil {
		fail(w, r, "request signing failed")
		return
	}
	// #nosec G710 -- redirects to the IdP SSO endpoint from its metadata.
	http.Redirect(w, r, redirect.String(), http.StatusTemporaryRedirect)
}

// Callback is the ACS endpoint: it verifies the SAML response, resolves the
// user, and issues a session.
func (h *samlFlow) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	st, err := h.state.Take(ctx, r.PostForm.Get("RelayState"))
	if err != nil || !checkFlowBinding(r, st.FlowCookie) {
		fail(w, r, "invalid or expired login")
		return
	}
	cfg, err := h.svc.loginProvider(ctx, st.ProviderID, MethodSAML)
	if err != nil {
		fail(w, r, "provider not configured")
		return
	}
	sp, err := h.serviceProvider(ctx, cfg.SAML, false)
	if err != nil {
		slog.Warn("saml callback: provider metadata invalid", "error", err, "provider", st.ProviderID)
		fail(w, r, "provider metadata invalid")
		return
	}
	assertion, err := sp.ParseResponse(r, []string{st.RequestID})
	if err != nil {
		// The IdP may have rotated its signing key since the metadata was
		// cached. Verify once more against fresh metadata.
		if sp, err = h.serviceProvider(ctx, cfg.SAML, true); err == nil {
			assertion, err = sp.ParseResponse(r, []string{st.RequestID})
		}
	}
	if err != nil {
		slog.Warn("saml callback: response verification failed", "error", err, "provider", st.ProviderID)
		fail(w, r, "response verification failed")
		return
	}
	opts := identity(assertion)
	if opts.Subject == "" {
		fail(w, r, "assertion has no subject")
		return
	}
	opts.ProviderID = cfg.ProviderID
	opts.WorkspaceID = cfg.WorkspaceID
	opts.JITProvisioning = cfg.SAML.JITProvisioning
	opts.LinkUserID = st.LinkUserID
	h.svc.completeSSO(w, r, h.linker, st.ReturnTo, opts)
}

// assertionAttributes flattens the assertion's attribute statements, keying
// each attribute by both Name (often a URI/OID) and FriendlyName, since IdPs
// use either spelling.
func assertionAttributes(a *saml.Assertion) map[string][]string {
	attrs := make(map[string][]string)
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			for _, v := range attr.Values {
				attrs[attr.Name] = append(attrs[attr.Name], v.Value)
				if attr.FriendlyName != "" {
					attrs[attr.FriendlyName] = append(attrs[attr.FriendlyName], v.Value)
				}
			}
		}
	}
	return attrs
}

// identity maps the assertion onto the linker options. The linker only
// trusts the email for the provider workspace's verified domains.
func identity(a *saml.Assertion) flowLinkOptions {
	attrs := assertionAttributes(a)

	var subject string
	if a.Subject != nil && a.Subject.NameID != nil {
		subject = a.Subject.NameID.Value
	}

	email := attrValue(attrs,
		"email", "emailaddress", "mail",
		"urn:oid:1.2.840.113549.1.9.1", // Keycloak / LDAP standard
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	)
	name := attrValue(attrs,
		"name", "displayName", "cn",
		"urn:oid:2.5.4.3", // X.500 Common Name
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
	)

	if name == "" {
		givenName := attrValue(attrs,
			"givenName",
			"urn:oid:2.5.4.42",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
		)
		surname := attrValue(attrs,
			"sn", "surname",
			"urn:oid:2.5.4.4",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		)
		name = strings.TrimSpace(givenName + " " + surname)
	}

	// An IdP that sends no NameID falls back to the email attribute: NameID
	// formats vary per IdP and the email is the only universally present
	// identifier, so it becomes the stable linking subject.
	if subject == "" {
		subject = email
	}

	return flowLinkOptions{
		Subject:       subject,
		Email:         normalizeEmail(email),
		EmailVerified: true,
		Name:          name,
		Picture:       attrValue(attrs, "picture"),
	}
}

// idpMetadata loads the IdP metadata. Fetched metadata is reused for
// providerCacheTTL, so IdP certificate rollovers arrive without anyone
// touching the configuration. refresh forces a fetch, at most once a
// minute. When the IdP's metadata endpoint is down, the last good copy
// keeps logins working.
func (h *samlFlow) idpMetadata(ctx context.Context, cfg *SAMLIDP, refresh bool) (*saml.EntityDescriptor, error) {
	if len(cfg.MetadataXML) > 0 {
		ed := &saml.EntityDescriptor{}
		if err := xml.Unmarshal(cfg.MetadataXML, ed); err != nil {
			return nil, err
		}
		return ed, validMetadata(ed)
	}

	h.mu.Lock()
	cached, ok := h.metas[cfg.MetadataURL]
	h.mu.Unlock()
	age := time.Since(cached.at)
	if ok && (age < time.Minute || !refresh && age < providerCacheTTL) {
		return cached.ed, nil
	}

	u, err := url.Parse(cfg.MetadataURL)
	if err != nil {
		return nil, err
	}
	ed, err := samlsp.FetchMetadata(ctx, h.svc.idp, *u)
	if err == nil {
		err = validMetadata(ed)
	}
	if err != nil {
		if ok {
			slog.Warn("saml: metadata refresh failed, using the last good copy", "error", err, "url", cfg.MetadataURL)
			return cached.ed, nil
		}
		return nil, err
	}
	h.mu.Lock()
	h.metas[cfg.MetadataURL] = fetchedMetadata{ed: ed, at: time.Now()}
	h.mu.Unlock()
	return ed, nil
}

func validMetadata(ed *saml.EntityDescriptor) error {
	if len(ed.IDPSSODescriptors) == 0 {
		return errors.New("saml: metadata has no IDPSSODescriptor")
	}
	return nil
}

// Metadata serves the SP metadata for the IdP administrator.
func (h *samlFlow) Metadata(w http.ResponseWriter, _ *http.Request) {
	buf, err := xml.MarshalIndent(h.sp(nil).Metadata(), "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate metadata")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf)
}

// Certificate serves the SP certificate as PEM.
func (h *samlFlow) Certificate(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(h.certPEM)
}

func (h *samlFlow) serviceProvider(ctx context.Context, cfg *SAMLIDP, refresh bool) (*saml.ServiceProvider, error) {
	ed, err := h.idpMetadata(ctx, cfg, refresh)
	if err != nil {
		return nil, err
	}
	return h.sp(ed), nil
}

func (h *samlFlow) sp(ed *saml.EntityDescriptor) *saml.ServiceProvider {
	acs, _ := url.Parse(h.svc.baseURL + "/saml/acs")
	meta, _ := url.Parse(h.svc.baseURL + "/saml/metadata")
	return &saml.ServiceProvider{
		EntityID:    meta.String(),
		Key:         h.spKey,
		Certificate: h.spCert,
		AcsURL:      *acs,
		MetadataURL: *meta,
		IDPMetadata: ed,
	}
}

// samlKeypair returns the SP keypair PEMs, generating and storing a fresh
// self-signed pair on first boot. The key column encrypts at rest through
// its sqlc type.
func (s *Service) samlKeypair(ctx context.Context) (keyPEM, certPEM []byte, err error) {
	row, err := s.sys.GetSAMLKeypair(ctx)
	if err == nil {
		return row.KeyEnc, row.CertPem, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, err
	}
	keyPEM, certPEM, err = generateSAMLKeypair()
	if err != nil {
		return nil, nil, err
	}
	stored, err := s.sys.PutSAMLKeypair(ctx, &db.PutSAMLKeypairParams{KeyEnc: keyPEM, CertPem: certPEM})
	if err != nil {
		return nil, nil, err
	}
	return stored.KeyEnc, stored.CertPem, nil
}

func parseSAMLKeypair(keyPEM, certPEM []byte) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	certBlock, _ := pem.Decode(certPEM)
	if keyBlock == nil || certBlock == nil {
		return nil, nil, errors.New("saml: invalid keypair PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

// generateSAMLKeypair returns the SP keypair as PEM. The certificate never
// expires (RFC 5280 4.1.2.5): SAML treats metadata certificates as bare keys,
// nokku does not sign requests, and IdPs that encrypt assertions pin this
// key, so rotating it would only break them.
func generateSAMLKeypair() (keyPEM, certPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nokku-saml-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(
		&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
	)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return keyPEM, certPEM, nil
}
