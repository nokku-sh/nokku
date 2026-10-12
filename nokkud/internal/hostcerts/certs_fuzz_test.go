package hostcerts

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

// Arbitrary control-plane bytes must never panic, and only host certificates that round-trip are accepted.
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
		if cert.CertType != ssh.HostCert {
			t.Fatalf(
				"parseCertificateBytes accepted cert with type %d, want %d",
				cert.CertType,
				ssh.HostCert,
			)
		}
		if _, _, _, _, err = ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(cert)); err != nil {
			t.Fatalf("accepted certificate does not round-trip: %v", err)
		}
		_ = isValid(cert, "")
		_ = isValid(cert, "some-target-id")
	})
}

// Whatever is stored must be signed by the trusted CA and leave a parseable file behind.
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
		if err != nil {
			t.Fatalf("saveCertificate succeeded but the certificate does not load: %v", err)
		}
		if !signedBy(cert, ca.pub) {
			t.Fatal("saveCertificate stored a certificate of another CA")
		}
	})
}
