// Package webpki is the server's TLS identity as clients see it. The client side is internal/trust.
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
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/realip"
)

// Path is where clients look for the CA.
const Path = "/ca.crt"

type envConfig struct {
	// CAFile is the CA of the proxy's certificate in PEM, when that is a private one.
	CAFile string `env:"NOKKU_TLS_CA"`
}

// Identity is the certificate the server answers with, and the CA a client is told for the certificate it saw.
type Identity struct {
	// builtin signs the server's own certificate, proxy is NOKKU_TLS_CA.
	builtin, proxy bundle
	cert           func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// bundle is what clients are told to trust. The zero value is nothing.
type bundle struct {
	pem []byte
	pin string
}

// New loads the built-in CA and makes it on the first start. host is the name its certificate is for.
func New(ctx context.Context, conn *db.Connection, host string) (*Identity, error) {
	cfg, err := env.ParseAs[envConfig]()
	if err != nil {
		return nil, err
	}
	id := &Identity{}
	if cfg.CAFile != "" {
		cas, err := readCAs(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("NOKKU_TLS_CA: %w", err)
		}
		id.proxy = advertise(cas...)
		slog.Info("a client behind the proxy is told the CA in NOKKU_TLS_CA", "pin", id.proxy.pin)
	}
	ca, err := loadIssuer(ctx, conn, host)
	if err != nil {
		return nil, fmt.Errorf("built-in CA: %w", err)
	}
	id.cert = ca.certificate
	id.builtin = advertise(ca.root)
	slog.Info("a client that connects without a proxy gets a certificate from the built-in CA", "pin", id.builtin.pin)
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

// advertise is what clients are told to trust. The pin is the one of the first certificate.
func advertise(cas ...*x509.Certificate) bundle {
	sum := sha256.Sum256(cas[0].RawSubjectPublicKeyInfo)
	b := bundle{pin: "sha256:" + hex.EncodeToString(sum[:])}
	for _, ca := range cas {
		b.pem = append(b.pem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	return b
}

// seen is the CA behind the certificate this client saw. A proxy with a public one and plain localhost need none.
func (i *Identity) seen(meta actor.RequestMeta) bundle {
	switch {
	case realip.Proto(meta.Header, meta.RemoteAddr) == "https":
		return i.proxy
	case meta.TLS:
		return i.builtin
	}
	return bundle{}
}

// Pin is sha256 over the public key of the CA this client has to know, empty when it needs none.
func (i *Identity) Pin(meta actor.RequestMeta) string { return i.seen(meta).pin }

func (i *Identity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ca := i.seen(actor.RequestMeta{Header: r.Header, RemoteAddr: r.RemoteAddr, TLS: r.TLS != nil})
	if ca.pem == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(ca.pem)
}
