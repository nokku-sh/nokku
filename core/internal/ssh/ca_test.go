package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	signer := func(k caKey) ssh.Signer {
		s, err := getSigner(k.private)
		require.NoError(t, err)
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
	require.NoError(t, err)
	pubStr, err := MarshalPubKey(pub)
	require.NoError(t, err)
	return pubStr
}

func parseKey(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err, "failed to parse CA public key")
	return key
}

// checkCert verifies cert as sshd and ssh do, against the key of its kind.
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
	// CheckCert skips who signed, sshd asks IsUserAuthority first.
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
	require.NoError(t, err)
	assert.NotEqual(t, user.public, host.public, "the user and the host key must differ")
	info := NewCA()
	assert.Equal(t, 16*time.Hour, info.UserDefaultTtl)
	assert.Equal(t, 7*24*time.Hour, info.UserMaxTtl)
	for name, key := range map[string]caKey{"user": user, "host": host} {
		assert.Equal(t, ssh.KeyAlgoED25519, parseKey(t, key.public).Type(), "%s key", name)
		_, err := x509.ParsePKCS8PrivateKey(key.private)
		assert.NoError(t, err, "%s private key is not PKCS#8", name)
	}
}
