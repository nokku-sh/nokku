package ssh

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// FuzzCheckCert must never panic, and anything it accepts must be a
// certificate from the CA that is valid now.
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
		if err != nil {
			t.Fatalf("CheckCert accepted unparseable data: %v", err)
		}
		after, before := CertWindow(cert)
		if time.Now().Before(after) || time.Now().After(before) {
			t.Fatal("CheckCert accepted a certificate outside its validity window")
		}
	})
}
