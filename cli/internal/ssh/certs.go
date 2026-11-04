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

// CheckCert wants a certificate from caKey, valid for at least margin.
func CheckCert(data []byte, caKey string, margin time.Duration) error {
	cert, err := ParseCert(data)
	if err != nil {
		return err
	}
	if !signedBy(cert, caKey) {
		return errors.New("certificate signed by a different CA")
	}
	if !within(cert, margin) {
		return errors.New("certificate expired or not yet valid")
	}
	return nil
}

// CertValid wants a certificate the target takes, valid for at least margin.
func CertValid(target state.Target, ca state.CA, margin time.Duration) bool {
	cert, err := readCert(target.ID)
	return err == nil && (target.Behind(ca) || signedBy(cert, ca.PublicKey)) && within(cert, margin)
}

// CertFresh ends at half life, so a core outage leaves a user half a lifetime.
func CertFresh(target state.Target, ca state.CA) bool {
	cert, err := readCert(target.ID)
	if err != nil {
		return false
	}
	// It refuses every cert of the new key, so keep the old one while it works, even for fewer accounts.
	if target.Behind(ca) {
		return within(cert, 0)
	}
	after, before := CertWindow(cert)
	return covers(cert, target.Usernames) && signedBy(cert, ca.PublicKey) && within(cert, before.Sub(after)/2)
}

// CertCovers is false for a certificate older than a grant.
func CertCovers(target state.Target) bool {
	cert, err := readCert(target.ID)
	return err == nil && covers(cert, target.Usernames)
}

func readCert(targetID string) (*ssh.Certificate, error) {
	data, err := os.ReadFile(paths.SSHCertificate(targetID))
	if err != nil {
		return nil, err
	}
	return ParseCert(data)
}

func signedBy(cert *ssh.Certificate, caKey string) bool {
	ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
	return err == nil && cert.SignatureKey != nil && bytes.Equal(cert.SignatureKey.Marshal(), ca.Marshal())
}

// Relies on the core's principals ending in ":" and the account.
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

func within(cert *ssh.Certificate, margin time.Duration) bool {
	after, before := CertWindow(cert)
	return !time.Now().Before(after) && time.Until(before) > margin
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
