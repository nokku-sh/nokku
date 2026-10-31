package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// testCA is a CA row with the two signers CASigner would hand out for it.
type testCA struct {
	row        *db.SSHCA
	user, host ssh.Signer
}

func newTestCA(t *testing.T) testCA {
	t.Helper()

	user, host, err := newKeys()
	if err != nil {
		t.Fatalf("newKeys failed: %v", err)
	}
	signer := func(k caKey) ssh.Signer {
		s, err := getSigner(k.private)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	return testCA{
		row: &db.SSHCA{
			PublicKey:      user.public,
			HostPublicKey:  host.public,
			UserDefaultTtl: 24 * time.Hour,
			UserMaxTtl:     168 * time.Hour,
			HostTtl:        2160 * time.Hour,
		},
		user: signer(user),
		host: signer(host),
	}
}

func newTestKey(t *testing.T) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubStr, err := MarshalPubKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pubStr
}

func parseKey(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("failed to parse CA public key: %v", err)
	}
	return key
}

// checkCert verifies cert the way sshd and ssh do, a user certificate against the user key, a host one against the
// host key.
func checkCert(t *testing.T, ca *db.SSHCA, cert *ssh.Certificate, principal string) error {
	t.Helper()
	user, host := parseKey(t, ca.PublicKey), parseKey(t, ca.HostPublicKey)
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), user.Marshal())
		},
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return bytes.Equal(auth.Marshal(), host.Marshal())
		},
	}
	if cert.CertType == ssh.HostCert {
		return checker.CheckHostKey(principal+":22", nil, cert)
	}
	// CheckCert checks the signature but not who made it, sshd asks IsUserAuthority first.
	if !checker.IsUserAuthority(cert.SignatureKey) {
		return errors.New("the certificate does not come from the user key")
	}
	return checker.CheckCert(principal, cert)
}

func validity(cert *ssh.Certificate) time.Duration {
	return time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
}

func TestNewCA(t *testing.T) {
	user, host, err := newKeys()
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]caKey{"user": user, "host": host} {
		if got := parseKey(t, key.public).Type(); got != ssh.KeyAlgoED25519 {
			t.Errorf("%s key is %s, want Ed25519", name, got)
		}
		if _, err := x509.ParsePKCS8PrivateKey(key.private); err != nil {
			t.Errorf("%s private key is not PKCS#8: %v", name, err)
		}
	}
	if user.public == host.public {
		t.Error("the user and the host key must differ")
	}
	info := NewCA()
	if info.UserDefaultTtl != 16*time.Hour || info.UserMaxTtl != 7*24*time.Hour {
		t.Errorf("user certificates default to %v, at most %v", info.UserDefaultTtl, info.UserMaxTtl)
	}
}
