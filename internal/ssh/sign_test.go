package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

func TestSignCertificate_UnspecifiedTypeIsUser(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(ca, newTestKey(t), "alice", "k", time.Hour,
		nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("SignCertificate() error: %v", err)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %v, want UserCert", cert.CertType)
	}
}

func TestSignCertificate_Errors(t *testing.T) {
	ca := newTestCA(t)
	clientKey := newTestKey(t)

	badCA := &db.CertificateAuthority{PrivateKey: []byte("garbage")}

	rsaOnly := newTestCA(t)
	rsaOnly.AllowedKeyTypes = []nokkuv1.CertificateKeyType{
		nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA,
	}

	badExt := newTestCA(t)
	badExt.UserExtensions = []byte("::: not yaml")

	badOpts := newTestCA(t)
	badOpts.UserCriticalOptions = []byte("::: not yaml")

	tests := []struct {
		name    string
		ca      *db.CertificateAuthority
		pub     string
		wantErr string
	}{
		{"invalid CA key", badCA, clientKey, "CA signer"},
		{"invalid public key", ca, "not-a-key", "public key"},
		{"disallowed key type", rsaOnly, clientKey, "not allowed"},
		{"bad extensions", badExt, clientKey, "extensions"},
		{"bad critical options", badOpts, clientKey, "critical options"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignCertificate(tt.ca, tt.pub, "alice", "k", time.Hour,
				nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_USER)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestBoundTTL(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"zero", 0, time.Hour},
		{"negative", -time.Minute, time.Hour},
		{"over max", 48 * time.Hour, time.Hour},
		{"in range", 30 * time.Minute, 30 * time.Minute},
		{"exactly max", 24 * time.Hour, 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boundTTL(tt.ttl, time.Hour, 24*time.Hour); got != tt.want {
				t.Errorf("boundTTL(%v) = %v, want %v", tt.ttl, got, tt.want)
			}
		})
	}
}

func TestIsAllowedKeyType_WeakRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	allowed := []nokkuv1.CertificateKeyType{nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA}
	if err := isAllowedKeyType(allowed, pub); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("error = %v, want weak-key rejection", err)
	}

	key2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub2048, err := ssh.NewPublicKey(&key2048.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := isAllowedKeyType(allowed, pub2048); err != nil {
		t.Errorf("2048-bit RSA rejected: %v", err)
	}
}

func TestGetKeyType(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _ := ssh.NewPublicKey(priv.Public())

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, _ := ssh.NewPublicKey(&rsaKey.PublicKey)

	tests := []struct {
		name string
		pub  ssh.PublicKey
		want nokkuv1.CertificateKeyType
	}{
		{"ed25519", edPub, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519},
		{"rsa", rsaPub, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getKeyType(tt.pub)
			if err != nil {
				t.Fatalf("getKeyType() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("getKeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserPermissions_BadInput(t *testing.T) {
	ca := newTestCA(t)
	ca.UserCriticalOptions = []byte("::: not yaml")
	if _, err := userPermissions(ca); err == nil {
		t.Error("expected error for invalid critical options")
	}
}

func TestSignUserCertificate(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(
		ca,
		newTestKey(t),
		"user-123",
		"nokku:login:user:alice:user-123",
		0,
		nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_USER,
	)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("expected user cert, got %d", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "user-123" {
		t.Errorf("unexpected principals: %v", cert.ValidPrincipals)
	}
	if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok {
		t.Errorf("expected permit-pty extension, got %v", cert.Permissions.Extensions)
	}
	// Default user TTL is 24h (plus 1m clock-skew allowance on ValidAfter)
	if v := validity(cert); v < 24*time.Hour || v > 24*time.Hour+2*time.Minute {
		t.Errorf("expected ~24h validity, got %v", v)
	}
	checkCert(t, ca, cert, "user-123")
}

func TestSignHostCertificate(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(
		ca,
		newTestKey(t),
		"target-123",
		"nokku:provision:daemon:d:d",
		0,
		nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_HOST,
	)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	if cert.CertType != ssh.HostCert {
		t.Errorf("expected host cert, got %d", cert.CertType)
	}
	if len(cert.Permissions.Extensions) != 0 {
		t.Errorf("host certs must not carry user extensions: %v", cert.Permissions.Extensions)
	}
	// Host default TTL is 2160h (90 days)
	if v := validity(cert); v < 2160*time.Hour || v > 2160*time.Hour+2*time.Minute {
		t.Errorf("expected ~2160h validity, got %v", v)
	}
	checkCert(t, ca, cert, "target-123")
}

func TestSignCertificateTTLBounds(t *testing.T) {
	ca := newTestCA(t)

	// Negative TTL falls back to the default instead of expiring instantly
	cert, err := SignCertificate(ca, newTestKey(t), "u", "k", -time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v := validity(cert); v < 24*time.Hour {
		t.Errorf("negative TTL should fall back to default, got %v", v)
	}

	// Over-max TTL falls back to the default
	cert, err = SignCertificate(ca, newTestKey(t), "u", "k", 1000*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v := validity(cert); v > 25*time.Hour {
		t.Errorf("over-max TTL should fall back to default, got %v", v)
	}

	// In-bounds TTL is honored
	cert, err = SignCertificate(ca, newTestKey(t), "u", "k", 2*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v := validity(cert); v < 2*time.Hour || v > 2*time.Hour+2*time.Minute {
		t.Errorf("expected ~2h validity, got %v", v)
	}
}

func TestSignCertificateRespectsAllowedKeyTypes(t *testing.T) {
	ca := newTestCA(t)
	ca.AllowedKeyTypes = []nokkuv1.CertificateKeyType{
		nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519,
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := MarshalPubKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignCertificate(ca, rsaPub, "u", "k", 0, 0); err == nil {
		t.Error("expected RSA key to be rejected by ED25519-only policy")
	}
}
