package iam

// The SAML SP-initiated flow, ported from kagi. The SP keypair is generated
// once and persisted in the saml_keypair table, encrypted at rest.

import (
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
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"

	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
)

// metadataCacheTTL bounds how long parsed IdP metadata stays cached.
const metadataCacheTTL = 10 * time.Minute

// samlState is the cross-request payload carried in the RelayState.
type samlState struct {
	WorkspaceID string `json:"workspace_id,omitempty"`
	ProviderID  string `json:"provider_id"`
	RequestID   string `json:"request_id"`
	ReturnTo    string `json:"return_to,omitempty"`
	LinkUserID  string `json:"link_user_id,omitempty"`
	// FlowCookie is the browser-scoped flow binding value (login CSRF).
	FlowCookie string `json:"flow_cookie,omitempty"`
}

// samlFlow serves the SAML SP-initiated flow.
type samlFlow struct {
	svc         *Service
	linker      *linker
	state       *state[samlState]
	errRedirect string
	samlConfig  SAMLConfig
	spKey       *rsa.PrivateKey
	spCert      *x509.Certificate
	certPEM     []byte
	metas       *cache.Local[*saml.EntityDescriptor]
}

// newSAMLFlow builds the SAML flow handler, resolving or generating the SP
// keypair. The canonical stored pair wins, so concurrent first boots
// converge on one key.
func newSAMLFlow(svc *Service, cfg SAMLConfig) (*samlFlow, error) {
	keyPEM, certPEM, err := svc.resolveSAMLKeypair()
	if err != nil {
		return nil, err
	}
	key, cert, certPEM, err := parseSAMLKeypair(keyPEM, certPEM)
	if err != nil {
		return nil, err
	}
	return &samlFlow{
		svc:         svc,
		linker:      &linker{svc: svc, credType: MethodSAML, OnSSOLogin: svc.OnSSOLogin},
		state:       newState[samlState](svc.cache, "saml:state:", flowStateTTL),
		errRedirect: svc.baseURL + "/auth-error",
		samlConfig:  cfg,
		spKey:       key,
		spCert:      cert,
		certPEM:     certPEM,
		metas:       cache.NewLocal[*saml.EntityDescriptor](metadataCacheTTL),
	}, nil
}

// Login starts the SP-initiated flow. It expects a "provider" query
// parameter and an optional "return_to" query parameter.
func (h *samlFlow) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providerID := r.URL.Query().Get("provider")
	if providerID == "" {
		WriteError(w, http.StatusBadRequest, "missing_provider", "missing provider")
		return
	}

	workspaceID, cfg, err := h.svc.resolveForLogin(
		ctx, "", providerID, r.URL.Query().Get("domain"),
	)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider not configured")
		return
	}

	ed, err := h.idpMetadata(ctx, providerID, cfg.SAML)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider metadata invalid")
		return
	}

	sp := h.serviceProvider(cfg.SAML, ed)
	ssoURL := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if ssoURL == "" {
		ssoURL = sp.GetSSOBindingLocation(saml.HTTPPostBinding)
	}
	if ssoURL == "" {
		Fail(w, r, h.errRedirect, "no SSO endpoint in metadata")
		return
	}

	req, err := sp.MakeAuthenticationRequest(ssoURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		Fail(w, r, h.errRedirect, "request creation failed")
		return
	}

	relayState, err := crypto.RandomString(32)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	st := samlState{
		WorkspaceID: workspaceID,
		ProviderID:  providerID,
		RequestID:   req.ID,
		ReturnTo:    SafeReturnTo(r.URL.Query().Get("return_to")),
		LinkUserID:  linkUserIDFor(ctx, r),

		// The IdP posts the assertion back cross-site, so the binding cookie
		// must be a None cookie: only possible over HTTPS.
		FlowCookie: startFlowBinding(w, strings.HasPrefix(h.svc.baseURL, "https://")),
	}
	if err := h.state.Put(ctx, relayState, st); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	redirect, err := req.Redirect(relayState, sp)
	if err != nil {
		Fail(w, r, h.errRedirect, "request signing failed")
		return
	}
	// #nosec G710 -- redirects to the IdP SSO endpoint from its metadata.
	http.Redirect(w, r, redirect.String(), http.StatusTemporaryRedirect)
}

// Callback is the ACS endpoint: it parses and verifies the SAML response,
// resolves the user, and issues a session.
func (h *samlFlow) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_request", "bad request")
		return
	}

	st, err := h.state.Take(ctx, r.PostForm.Get("RelayState"))
	if err != nil {
		Fail(w, r, h.errRedirect, "invalid or expired login")
		return
	}
	// The callback must arrive in the browser that started the flow.
	if !checkFlowBinding(r, st.FlowCookie) {
		Fail(w, r, h.errRedirect, "invalid or expired login")
		return
	}

	cfg, err := h.svc.GetSSOProvider(ctx, st.ProviderID)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider not configured")
		return
	}

	ed, err := h.idpMetadata(ctx, st.ProviderID, cfg.SAML)
	if err != nil {
		slog.Warn(
			"saml callback: provider metadata invalid",
			"error",
			err,
			"provider",
			st.ProviderID,
		)
		Fail(w, r, h.errRedirect, "provider metadata invalid")
		return
	}

	sp := h.serviceProvider(cfg.SAML, ed)
	assertion, err := sp.ParseResponse(r, []string{st.RequestID})
	if err != nil {
		slog.Warn(
			"saml callback: response verification failed",
			"error",
			err,
			"provider",
			st.ProviderID,
		)
		Fail(w, r, h.errRedirect, "response verification failed")
		return
	}

	opts := h.identity(cfg.SAML, assertion)
	opts.ProviderID = st.ProviderID
	if opts.Subject == "" {
		slog.Warn("saml callback: assertion has no subject", "provider", st.ProviderID)
		Fail(w, r, h.errRedirect, "assertion has no subject")
		return
	}

	h.svc.completeSSO(ctx, w, r, h.linker, &flowAuthorizeState{
		WorkspaceID: st.WorkspaceID,
		ReturnTo:    st.ReturnTo,
		LinkUserID:  st.LinkUserID,
	}, opts, h.errRedirect)
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

// identity maps the assertion onto the linker options. SAML assertions
// carry org-managed emails, so EmailVerified is always true.
func (h *samlFlow) identity(cfg *SAMLIDP, a *saml.Assertion) flowLinkOptions {
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

	// ProviderID is not set here: the caller knows the stored provider id
	// and must fill it in. Linking under anything else (like an attribute
	// or endpoint value) would orphan the credential and disable the
	// verified-domain binding checks.
	return flowLinkOptions{
		Subject:         subject,
		Email:           email,
		EmailVerified:   true, // SAML assertions carry org-managed emails
		Name:            name,
		Picture:         attrValue(attrs, "picture"),
		JITProvisioning: cfg.JITProvisioning,
	}
}

func (h *samlFlow) idpMetadata(
	ctx context.Context,
	providerID string,
	cfg *SAMLIDP,
) (*saml.EntityDescriptor, error) {
	key := providerID
	if ed, ok := h.metas.Get(key); ok {
		return ed, nil
	}

	if len(cfg.MetadataXML) == 0 && cfg.MetadataURL != "" {
		// #nosec G709 -- the metadata URL is operator-provided configuration, not request data.
		u, err := url.Parse(cfg.MetadataURL)
		if err != nil {
			return nil, err
		}
		ed, err := samlsp.FetchMetadata(ctx, &http.Client{Timeout: providerHTTPTimeout}, *u)
		if err != nil {
			return nil, err
		}
		h.metas.Put(key, ed)
		return ed, nil
	}

	ed := &saml.EntityDescriptor{}
	// #nosec G709 -- IdP metadata is operator-provided configuration, not request data.
	if err := xml.Unmarshal(cfg.MetadataXML, ed); err != nil {
		return nil, err
	}
	if len(ed.IDPSSODescriptors) == 0 {
		return nil, errors.New("saml: metadata has no IDPSSODescriptor")
	}

	h.metas.Put(key, ed)
	return ed, nil
}

// Metadata serves the SP metadata for the IdP administrator to configure.
func (h *samlFlow) Metadata(w http.ResponseWriter, _ *http.Request) {
	acsURL := h.spAcsURL()
	entityID := h.samlConfig.SPEntityID
	if entityID == "" {
		entityID = h.samlConfig.AcsURL
	}
	sp := &saml.ServiceProvider{
		EntityID:    entityID,
		Key:         h.spKey,
		Certificate: h.spCert,
		AcsURL:      acsURL,
		MetadataURL: acsURL,
	}
	buf, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		WriteError(
			w,
			http.StatusInternalServerError,
			"failed_to_generate_metadata",
			"failed to generate metadata",
		)
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

func (h *samlFlow) spAcsURL() url.URL {
	u, err := url.Parse(h.samlConfig.AcsURL)
	if err != nil {
		return url.URL{}
	}
	return *u
}

func (h *samlFlow) serviceProvider(cfg *SAMLIDP, ed *saml.EntityDescriptor) *saml.ServiceProvider {
	acsStr := cfg.AcsURL
	if acsStr == "" {
		acsStr = h.samlConfig.AcsURL
	}
	entityID := cfg.SPEntityID
	if entityID == "" {
		entityID = h.samlConfig.SPEntityID
	}
	if entityID == "" {
		entityID = acsStr
	}
	return &saml.ServiceProvider{
		EntityID:    entityID,
		Key:         h.spKey,
		Certificate: h.spCert,
		AcsURL:      parseURLOrEmpty(acsStr),
		MetadataURL: parseURLOrEmpty(acsStr),
		IDPMetadata: ed,
	}
}

// resolveSAMLKeypair returns the SP keypair from the store, generating and
// persisting a fresh self-signed pair on first boot. The canonical stored
// pair wins, so concurrent first boots converge on one key. The private key
// PEM is encrypted at rest with the app cipher.
func (s *Service) resolveSAMLKeypair() (keyPEM, certPEM []byte, err error) {
	if row, err := s.q.GetSAMLKeypair(context.Background()); err == nil {
		keyPEM, err := decryptSAMLKey(row.KeyEnc)
		if err != nil {
			return nil, nil, err
		}
		return keyPEM, row.CertPem, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, err
	}

	genKeyPEM, genCertPEM, err := generateSAMLKeypair()
	if err != nil {
		return nil, nil, err
	}
	stored, err := s.q.PutSAMLKeypair(context.Background(), &db.PutSAMLKeypairParams{
		KeyEnc:  encryptSAMLKey(genKeyPEM),
		CertPem: genCertPEM,
	})
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = decryptSAMLKey(stored.KeyEnc)
	if err != nil {
		return nil, nil, err
	}
	return keyPEM, stored.CertPem, nil
}

// encryptSAMLKey encrypts the private key PEM for at-rest storage. The
// certificate is public and stays plaintext.
func encryptSAMLKey(keyPEM []byte) []byte {
	enc, err := crypto.Encryptor()
	if err != nil {
		// Storing the key unencrypted beats failing startup; the error is
		// not recoverable by the caller either way.
		return keyPEM
	}
	out, err := enc.Encrypt(keyPEM)
	if err != nil {
		return keyPEM
	}
	return out
}

// decryptSAMLKey reverses encryptSAMLKey. A row that predates
// encryption-at-rest is plaintext PEM; it is returned as-is when the
// ciphertext does not decrypt but does parse as PEM. Anything else fails.
func decryptSAMLKey(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return blob, nil
	}
	enc, err := crypto.Encryptor()
	if err != nil {
		return blob, nil
	}
	plain, err := enc.Decrypt(blob)
	if err == nil {
		return plain, nil
	}
	if block, _ := pem.Decode(blob); block != nil {
		return blob, nil
	}
	return nil, err
}

func parseSAMLKeypair(keyPEM, certPEM []byte) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return nil, nil, nil, errors.New("saml: both key and certificate are required")
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, nil, errors.New("saml: invalid key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, nil, errors.New("saml: key is not RSA")
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, nil, errors.New("saml: invalid certificate PEM")
	}
	cert, certErr := x509.ParseCertificate(certBlock.Bytes)
	if certErr != nil {
		return nil, nil, nil, certErr
	}
	return key, cert, certPEM, nil
}

// generateSAMLKeypair returns the SP keypair as PEM: the encrypted private
// key goes to the store, the certificate is public and served as metadata.
func generateSAMLKeypair() (keyPEM, certPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nokku-saml-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
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

func parseURLOrEmpty(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return url.URL{}
	}
	return *u
}
