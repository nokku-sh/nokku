package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

func ParseCert(data []byte) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not an ssh certificate")
	}
	return cert, nil
}

func CertWindow(cert *ssh.Certificate) (after, before time.Time) {
	return unixTime(cert.ValidAfter), unixTime(cert.ValidBefore)
}

// CheckCert wants a certificate signed by caKey, valid now and for at least margin.
func CheckCert(data []byte, caKey string, margin time.Duration) error {
	cert, err := ParseCert(data)
	if err != nil {
		return err
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
	if err != nil {
		return fmt.Errorf("parse ca key: %w", err)
	}
	if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		return errors.New("certificate signed by a different CA")
	}
	after, before := CertWindow(cert)
	if time.Now().Before(after) || time.Until(before) <= margin {
		return errors.New("certificate expired or not yet valid")
	}
	return nil
}

func CertValid(target state.Target, ca state.CA, margin time.Duration) bool {
	data, err := os.ReadFile(paths.SSHCertificate(target.ID))
	return err == nil && CheckCert(data, ca.PublicKey, margin) == nil
}

// CertFresh ends at half the certificate's life, so a core outage finds an active user with half a lifetime left.
func CertFresh(target state.Target, ca state.CA) bool {
	data, err := os.ReadFile(paths.SSHCertificate(target.ID))
	if err != nil {
		return false
	}
	cert, err := ParseCert(data)
	if err != nil || !covers(cert, target.Usernames) {
		return false
	}
	after, before := CertWindow(cert)
	return CheckCert(data, ca.PublicKey, before.Sub(after)/2) == nil
}

// CertCovers is false for a certificate signed before a grant, the server refuses that account until renewal.
func CertCovers(target state.Target) bool {
	data, err := os.ReadFile(paths.SSHCertificate(target.ID))
	if err != nil {
		return false
	}
	cert, err := ParseCert(data)
	return err == nil && covers(cert, target.Usernames)
}

// Relies on one thing about the principals the core signs: each ends with ":" and its account.
func covers(cert *ssh.Certificate, accounts []string) bool {
	for _, account := range accounts {
		if !slices.ContainsFunc(cert.ValidPrincipals, func(p string) bool {
			return strings.HasSuffix(p, ":"+account)
		}) {
			return false
		}
	}
	return true
}

func unixTime(t uint64) time.Time {
	return time.Unix(int64(min(t, math.MaxInt64)), 0)
}

func CleanupCerts(keep []state.Target) error {
	files, err := paths.SSHCertificates()
	if err != nil {
		return err
	}
	valid := make(map[string]bool, len(keep))
	for _, t := range keep {
		valid[filepath.Base(paths.SSHCertificate(t.ID))] = true
	}
	for _, f := range files {
		if valid[filepath.Base(f)] {
			continue
		}
		if err = os.Remove(f); err != nil {
			return fmt.Errorf("remove stale certificate: %w", err)
		}
	}
	return nil
}
