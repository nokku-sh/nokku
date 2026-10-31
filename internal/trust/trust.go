// Package trust lets a client trust a Nokku server whose certificate comes
// from a private CA. The operator hands the client that CA as a PEM file, and
// the client verifies the server against the system roots plus that CA.
// Verification is never turned off.
package trust

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

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

// CheckBundle reports whether a PEM bundle holds at least one certificate and
// every certificate in it parses.
func CheckBundle(pemCAs []byte) error {
	found := false
	for block, rest := pem.Decode(pemCAs); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("trust: %w", err)
		}
		found = true
	}
	if !found {
		return errors.New("trust: no certificate in the CA data")
	}
	return nil
}
