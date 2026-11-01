// Package trust adds a private CA to the system roots, verification stays on.
package trust

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Untrusted is a TLS failure a CA would fix, unlike a wrong host or an expiry.
func Untrusted(err error) bool {
	_, ok := errors.AsType[x509.UnknownAuthorityError](err)
	return ok
}

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
