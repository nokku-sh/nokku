package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	kagisaml "github.com/mizuchilabs/kagi/saml"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
)

// SAMLHandler serves SAML SP-initiated SSO through kagi, backed by the
// deployment's single shared SP keypair.
type SAMLHandler struct {
	cfg     *config.Config
	handler *kagisaml.Handler
	keyPEM  []byte
	certPEM []byte
}

func NewSAMLHandler(cfg *config.Config) (*SAMLHandler, error) {
	keyPEM, certPEM, err := auth.EnsureSAMLSPKey(context.Background(), cfg.Conn)
	if err != nil {
		return nil, err
	}
	h, err := kagisaml.New(cfg.Auth.Kagi, kagisaml.Options{
		Cache:         cfg.Cache,
		Key:           keyPEM,
		Certificate:   certPEM,
		ErrorRedirect: cfg.FullURL() + "/auth-error",
	})
	if err != nil {
		return nil, err
	}
	return &SAMLHandler{cfg: cfg, handler: h, keyPEM: keyPEM, certPEM: certPEM}, nil
}

func (s *SAMLHandler) Login(w http.ResponseWriter, r *http.Request) {
	s.handler.Login(w, r)
}

func (s *SAMLHandler) Callback(w http.ResponseWriter, r *http.Request) {
	s.handler.Callback(w, r)
}

// Metadata serves the SP metadata the IdP administrator configures on their
// side. It is the same for every workspace.
func (s *SAMLHandler) Metadata(w http.ResponseWriter, _ *http.Request) {
	sp, err := s.serviceProvider()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to build metadata")
		return
	}
	buf, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to generate metadata")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write(buf); err != nil { // #nosec G705
		slog.Error("failed to write metadata", "error", err)
	}
}

// Certificate serves the SP certificate as PEM, for IdPs that require it
// separately from the metadata.
func (s *SAMLHandler) Certificate(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="nokku-sp.pem"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write(s.certPEM); err != nil {
		slog.Error("failed to write certificate", "error", err)
	}
}

func (s *SAMLHandler) serviceProvider() (*saml.ServiceProvider, error) {
	keyBlock, _ := pem.Decode(s.keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid SP private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(s.certPEM)
	if certBlock == nil {
		return nil, errors.New("invalid SP certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	acsURL, err := url.Parse(s.cfg.FullURL() + "/saml/acs")
	if err != nil {
		return nil, err
	}
	return &saml.ServiceProvider{
		EntityID:    s.cfg.FullURL() + "/saml/metadata",
		Key:         key,
		Certificate: cert,
		AcsURL:      *acsURL,
		MetadataURL: *acsURL,
	}, nil
}
