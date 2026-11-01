package hostcerts

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Control-plane bytes must never panic. Only host certs that round-trip pass.
func FuzzParseCertificate(f *testing.F) {
	ca := newTestCA(f)
	certText := signHostCert(f, ca, newHostPub(f), "some-target-id", 0, ssh.CertTimeInfinity)
	f.Add(certText)
	f.Add([]byte(""))
	f.Add([]byte("not a key"))
	f.Add([]byte("ssh-ed25519 AAAA"))
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----"))

	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := parseCertificateBytes(data)
		if err != nil {
			return
		}
		require.Equal(t, uint32(ssh.HostCert), cert.CertType, "parseCertificateBytes accepted another cert type")
		_, _, _, _, err = ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(cert))
		require.NoError(t, err, "accepted certificate does not round-trip")
		_ = isValid(cert, "")
		_ = isValid(cert, "some-target-id")
	})
}

// What is stored must be signed by the trusted CA and leave a parseable file.
func FuzzSaveCertificate(f *testing.F) {
	ca := newTestCA(f)
	certText := signHostCert(f, ca, newHostPub(f), "some-target-id", 0, ssh.CertTimeInfinity)
	otherText := signHostCert(f, newTestCA(f), newHostPub(f), "some-target-id", 0, ssh.CertTimeInfinity)
	f.Add(certText)
	f.Add(otherText)
	f.Add([]byte("garbage"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, signedCert []byte) {
		t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
		if err := saveCertificate(signedCert, ca.pub); err != nil {
			return
		}
		cert, err := Load()
		require.NoError(t, err, "saveCertificate succeeded but the certificate does not load")
		require.True(t, signedBy(cert, ca.pub), "saveCertificate stored a certificate of another CA")
	})
}
