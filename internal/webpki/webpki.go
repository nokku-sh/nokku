// Package webpki is the server's TLS identity as clients see it. The client side is the trust package of mon.
package webpki

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/internal/db"
)

// Path is where clients look for the CA.
const Path = "/ca.crt"

// Mode is NOKKU_TLS: who holds the certificate.
type Mode string

const (
	// ModeOff serves plain HTTP, a proxy in front holds the certificate.
	ModeOff Mode = ""
	// ModeInternal serves a certificate from a CA the server makes for itself.
	ModeInternal Mode = "internal"
)

func (m *Mode) UnmarshalText(text []byte) error {
	switch mode := Mode(strings.ToLower(strings.TrimSpace(string(text)))); mode {
	case ModeOff, ModeInternal:
		*m = mode
		return nil
	}
	return fmt.Errorf("NOKKU_TLS is %q, it takes internal. Leave it unset behind a proxy", text)
}

type envConfig struct {
	// CAFile is the CA of the proxy's certificate in PEM, when that is a private one.
	CAFile string `env:"NOKKU_TLS_CA"`
}

// Identity is the certificate the server answers with and the CA it advertises. The zero value does neither.
type Identity struct {
	pem  []byte
	pin  string
	cert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// New sets up the identity for mode. host is the name the certificate is for, only ModeInternal uses conn.
func New(ctx context.Context, conn *db.Connection, mode Mode, host string) (*Identity, error) {
	cfg, err := env.ParseAs[envConfig]()
	if err != nil {
		return nil, err
	}
	id := &Identity{}
	if mode == ModeInternal {
		if cfg.CAFile != "" {
			return nil, errors.New("NOKKU_TLS_CA has no use with NOKKU_TLS=internal, the server advertises its own CA")
		}
		ca, err := loadIssuer(ctx, conn, host)
		if err != nil {
			return nil, fmt.Errorf("NOKKU_TLS=internal: %w", err)
		}
		id.cert = ca.certificate
		id.advertise(ca.root)
		return id, nil
	}
	if cfg.CAFile != "" {
		cas, err := readCAs(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("NOKKU_TLS_CA: %w", err)
		}
		id.advertise(cas...)
	}
	return id, nil
}

// The file is served to anyone who asks, so readCAs refuses one with a private key in it.
func readCAs(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator names the file
	if err != nil {
		return nil, err
	}
	var cas []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, errors.New("the file holds a private key, it takes the CA certificate only")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		cas = append(cas, cert)
	}
	if len(cas) == 0 {
		return nil, fmt.Errorf("no certificate in %s", path)
	}
	return cas, nil
}

// advertise sets what clients are told to trust. The pin is the one of the first certificate.
func (i *Identity) advertise(cas ...*x509.Certificate) {
	sum := sha256.Sum256(cas[0].RawSubjectPublicKeyInfo)
	i.pin = "sha256:" + hex.EncodeToString(sum[:])
	for _, ca := range cas {
		i.pem = append(i.pem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
}

// Pin is sha256 over the public key of the first certificate, empty when nothing is advertised.
func (i *Identity) Pin() string { return i.pin }

// TLSConfig is nil when a proxy in front serves. nk, nokkud and every current browser speak TLS 1.3.
func (i *Identity) TLSConfig() *tls.Config {
	if i.cert == nil {
		return nil
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: i.cert}
}

func (i *Identity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if i.pem == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(i.pem)
}
