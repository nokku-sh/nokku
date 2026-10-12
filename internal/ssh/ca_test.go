package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
)

func newTestCA(t *testing.T) *db.SSHCA {
	t.Helper()

	info, err := NewCA(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0, 8760*time.Hour)
	if err != nil {
		t.Fatalf("NewCA failed: %v", err)
	}
	return &db.SSHCA{
		PrivateKey:          info.PrivateKey,
		PublicKey:           info.PublicKey,
		KeyType:             info.KeyType,
		UserDefaultTtl:      24 * time.Hour,
		UserMaxTtl:          168 * time.Hour,
		HostDefaultTtl:      2160 * time.Hour,
		HostMaxTtl:          4320 * time.Hour,
		AllowedKeyTypes:     []nokkuv1.CertificateKeyType{1, 2, 3},
		UserCriticalOptions: []byte(`{}`),
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

func checkCert(t *testing.T, ca *db.SSHCA, cert *ssh.Certificate, principal string) {
	t.Helper()

	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil {
		t.Fatalf("failed to parse CA public key: %v", err)
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPub.Marshal())
		},
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return bytes.Equal(auth.Marshal(), caPub.Marshal())
		},
	}
	if err := checker.CheckCert(principal, cert); err != nil {
		t.Fatalf("certificate failed verification: %v", err)
	}
}

func validity(cert *ssh.Certificate) time.Duration {
	return time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
}

func TestNewCA(t *testing.T) {
	for _, kt := range []nokkuv1.CertificateKeyType{1, 2, 3} {
		info, err := NewCA(kt, 0, 8760*time.Hour)
		if err != nil {
			t.Fatalf("NewCA(%v) failed: %v", kt, err)
		}
		if info.KeyType != kt {
			t.Errorf("expected key type %v, got %v", kt, info.KeyType)
		}
		if info.PublicKey == "" {
			t.Error("expected authorized-key public key")
		}
		if len(info.PrivateKey.Bytes()) == 0 {
			t.Error("expected private key bytes")
		}
	}

	// Unspecified defaults to ED25519
	info, err := NewCA(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_UNSPECIFIED, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.KeyType != nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519 {
		t.Errorf("expected ED25519 default, got %v", info.KeyType)
	}
	if info.Lifetime != 365*24*time.Hour || !info.NotAfter.Equal(info.NotBefore.Add(info.Lifetime)) {
		t.Errorf("no lifetime should mean a year, got %v until %v", info.Lifetime, info.NotAfter)
	}
}

func TestGenerateKeyClampsBits(t *testing.T) {
	kp, err := GenerateKey(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if kp.Bits != 2048 {
		t.Errorf("expected RSA bits clamped to 2048, got %d", kp.Bits)
	}
	if _, ok := kp.Private.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", kp.Private)
	}

	kp, err = GenerateKey(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ECDSA, 123)
	if err != nil {
		t.Fatal(err)
	}
	if kp.Bits != 256 {
		t.Errorf("expected ECDSA bits clamped to 256, got %d", kp.Bits)
	}
}
