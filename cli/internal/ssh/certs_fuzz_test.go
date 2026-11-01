package ssh

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// FuzzCheckCert never panics, and what it accepts parses and is valid now.
func FuzzCheckCert(f *testing.F) {
	signer := newSigner(f)
	caKey := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	now := time.Now()
	for _, seed := range [][]byte{
		signCert(f, signer, now.Add(-time.Hour), now.Add(time.Hour)),
		signCert(f, signer, now.Add(-2*time.Hour), now.Add(-time.Hour)),
		ssh.MarshalAuthorizedKey(signer.PublicKey()),
		[]byte(""),
		[]byte("not-a-cert"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if CheckCert(data, caKey, 0) != nil {
			return
		}
		cert, err := ParseCert(data)
		require.NoError(t, err, "CheckCert accepted unparseable data")
		after, before := CertWindow(cert)
		require.WithinRange(t, time.Now(), after, before,
			"CheckCert accepted a certificate outside its validity window")
	})
}
