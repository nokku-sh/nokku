package hostcerts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/nokkud/internal/paths"
)

// Renewing at half the validity keeps the host verifiable through a backend outage of that length.
const renewFraction = 0.5

// SignFunc signs the host public key. Key and certificate are in authorized_keys form.
type SignFunc func(ctx context.Context, pub []byte) (string, error)

// ok is false when there is nothing to do, including when no host key exists yet.
func needsRenewal(targetID string, ca ssh.PublicKey) (pub []byte, ok bool) {
	pub, err := os.ReadFile(paths.HostKeyPub())
	if err != nil {
		return nil, false
	}
	cert, err := Load()
	if err != nil || !isValid(cert, targetID) || !matchesKey(cert, pub) || !signedBy(cert, ca) {
		return pub, true
	}
	return nil, false
}

// A cert for a previous key must be re-issued even inside its validity window.
func matchesKey(cert *ssh.Certificate, pub []byte) bool {
	key, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(pub))
	return err == nil && bytes.Equal(cert.Key.Marshal(), key.Marshal())
}

func signedBy(cert *ssh.Certificate, ca ssh.PublicKey) bool {
	return cert.SignatureKey != nil && bytes.Equal(cert.SignatureKey.Marshal(), ca.Marshal())
}

// RenewHostCerts reports whether a certificate was written. One from another CA than caKey is never stored.
func RenewHostCerts(ctx context.Context, targetID, caKey string, sign SignFunc) (bool, error) {
	if caKey == "" {
		return false, nil
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
	if err != nil {
		return false, fmt.Errorf("parse CA public key: %w", err)
	}
	pub, ok := needsRenewal(targetID, ca)
	if !ok {
		return false, nil
	}
	signed, err := sign(ctx, pub)
	if err != nil {
		return false, err
	}
	if err = saveCertificate([]byte(signed), ca); err != nil {
		return false, err
	}
	return true, nil
}

func NextRenewal(targetID, caKey string) time.Time {
	now := time.Now()

	cert, err := Load()
	if err != nil {
		slog.Debug("parse host certificate", "error", err)
		return now
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
	if err != nil || !isValid(cert, targetID) || !signedBy(cert, ca) {
		return now
	}
	// Nothing to renew. A CA change wakes the watcher by itself.
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return now.Add(24 * time.Hour)
	}

	renewalTime := renewalDeadline(cert)
	if renewalTime.Before(now) {
		return now
	}
	return renewalTime
}

func saveCertificate(signed []byte, ca ssh.PublicKey) error {
	cert, err := parseCertificateBytes(signed)
	if err != nil {
		return err
	}
	if !signedBy(cert, ca) {
		return errors.New("certificate is not signed by the trusted CA")
	}
	if err = fsutil.WriteIfChanged(paths.HostKeyCert(), ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

func isValid(cert *ssh.Certificate, targetID string) bool {
	now := time.Now()

	if targetID != "" {
		if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != targetID {
			return false
		}
	}
	if now.Before(uint64ToUnixTime(cert.ValidAfter)) {
		return false
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return true
	}
	return now.Before(renewalDeadline(cert))
}

func renewalDeadline(cert *ssh.Certificate) time.Time {
	validAfter := uint64ToUnixTime(cert.ValidAfter)
	validBefore := uint64ToUnixTime(cert.ValidBefore)
	return validBefore.Add(-time.Duration(float64(validBefore.Sub(validAfter)) * renewFraction))
}

func parseCertificateBytes(data []byte) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(data))
	if err != nil {
		return nil, err
	}

	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}

	if cert.CertType != ssh.HostCert {
		return nil, fmt.Errorf("not a host certificate (type %d)", cert.CertType)
	}
	return cert, nil
}

func Load() (*ssh.Certificate, error) {
	data, err := os.ReadFile(paths.HostKeyCert())
	if err != nil {
		return nil, err
	}
	return parseCertificateBytes(data)
}

func uint64ToUnixTime(t uint64) time.Time {
	if t > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(int64(t), 0)
}
