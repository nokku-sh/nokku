// Package trust lets a client trust a Nokku server whose certificate comes
// from a private CA. The server advertises its CA at CAPath. The client checks
// it against a pin it got out of band, keeps it, and from then on verifies the
// server the usual way against the system roots plus that CA. Verification is
// never turned off for a request that carries anything.
package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// CAPath is where a server advertises the CA its certificate comes from.
	CAPath = "/ca.crt"

	pinPrefix    = "sha256:"
	maxBundle    = 1 << 20
	fetchTimeout = 10 * time.Second
)

// ErrNoCA means the server advertises no CA, so there is nothing to pin.
var ErrNoCA = errors.New("trust: the server advertises no CA")

// Pin returns the pin of cert: "sha256:" and the hex SHA-256 of its public
// key. It survives a reissue of the certificate with the same key.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return pinPrefix + hex.EncodeToString(sum[:])
}

// ParsePin checks the shape of a pin and returns it in the form Pin writes.
func ParsePin(pin string) (string, error) {
	pin = strings.ToLower(strings.TrimSpace(pin))
	sum, ok := strings.CutPrefix(pin, pinPrefix)
	if raw, err := hex.DecodeString(sum); !ok || err != nil || len(raw) != sha256.Size {
		return "", errors.New("trust: a pin is sha256: followed by 64 hex characters")
	}
	return pin, nil
}

// Untrusted reports whether err is a TLS failure that a CA would fix: the
// server's certificate comes from an issuer this machine does not know. A
// wrong host name or an expired certificate is not.
func Untrusted(err error) bool {
	_, ok := errors.AsType[x509.UnknownAuthorityError](err)
	return ok
}

// Pool returns the system roots plus the certificates in pemCAs, which may be
// empty.
func Pool(pemCAs []byte) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if len(bytes.TrimSpace(pemCAs)) != 0 && !pool.AppendCertsFromPEM(pemCAs) {
		return nil, errors.New("trust: no certificate in the CA data")
	}
	return pool, nil
}

// ParseBundle returns the certificates of a PEM bundle.
func ParseBundle(pemCAs []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for block, rest := pem.Decode(pemCAs); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("trust: no certificate in the CA data")
	}
	return certs, nil
}

// Advertised fetches the CA certificates the server at apiURL advertises. The
// connection is not verified, so nothing it returns is trusted. It is there to
// show a fingerprint to a person. Use Bootstrap to get a CA to keep.
func Advertised(ctx context.Context, apiURL string) ([]*x509.Certificate, error) {
	// #nosec G402 -- the answer is public and only trusted once it matches a pin.
	body, err := fetch(ctx, apiURL, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	return ParseBundle(body)
}

// Bootstrap returns the PEM of the advertised CA that matches pin. It then
// connects once more with only that CA as a root, so a server that advertises
// a CA it has no certificate from is refused.
func Bootstrap(ctx context.Context, apiURL, pin string) ([]byte, error) {
	pin, err := ParsePin(pin)
	if err != nil {
		return nil, err
	}
	certs, err := Advertised(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		if Pin(cert) != pin {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		if _, err = fetch(ctx, apiURL, &tls.Config{RootCAs: roots}); err != nil {
			return nil, fmt.Errorf("trust: the server's certificate does not come from the pinned CA: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
	}
	return nil, errors.New(
		"trust: no CA of the server matches the pin, the pin is wrong or the connection is intercepted",
	)
}

func fetch(ctx context.Context, apiURL string, conf *tls.Config) ([]byte, error) {
	if !strings.HasPrefix(apiURL, "https://") {
		return nil, errors.New("trust: only an https server has a CA to trust")
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("trust: expected *http.Transport as default transport")
	}
	t := base.Clone()
	conf.MinVersion = tls.VersionTLS13
	t.TLSClientConfig = conf
	defer t.CloseIdleConnections()
	return get(ctx, &http.Client{Transport: t}, apiURL)
}

func get(ctx context.Context, httpc *http.Client, apiURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiURL, "/")+CAPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoCA
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust: fetching the CA: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBundle))
}
