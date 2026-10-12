package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"maps"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

func TestSignCertificate_UnspecifiedTypeIsUser(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(ca, newTestKey(t), []string{"alice"}, "k", time.Hour,
		0)
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

	badCA := &db.SSHCA{PrivateKey: []byte("garbage")}

	rsaOnly := newTestCA(t)
	rsaOnly.AllowedKeyTypes = []nokkuv1.CertificateKeyType{
		nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA,
	}

	tests := []struct {
		name    string
		ca      *db.SSHCA
		pub     string
		wantErr string
	}{
		{"invalid CA key", badCA, clientKey, "CA signer"},
		{"invalid public key", ca, "not-a-key", "public key"},
		{"disallowed key type", rsaOnly, clientKey, "not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignCertificate(tt.ca, tt.pub, []string{"alice"}, "k", time.Hour,
				ssh.UserCert)
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

func TestUserPermissions_Restrictions(t *testing.T) {
	ca := newTestCA(t)
	if got := userPermissions(ca).CriticalOptions; len(got) != 0 {
		t.Errorf("a CA without restrictions wrote %v", got)
	}

	ca.ForceCommand, ca.SourceAddress = "/usr/local/bin/backup", "10.0.0.0/8,192.0.2.7"
	want := map[string]string{"force-command": "/usr/local/bin/backup", "source-address": "10.0.0.0/8,192.0.2.7"}
	if got := userPermissions(ca).CriticalOptions; !maps.Equal(got, want) {
		t.Errorf("critical options = %v, want %v", got, want)
	}
}

// sshd and nokkud split the list on commas and trim nothing, so it is stored the way they read it.
func TestSourceAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"":                            "",
		" , ":                         "",
		"10.0.0.0/8, 192.168.1.10":    "10.0.0.0/8,192.168.1.10",
		" 2001:db8::/32 ,2001:db8::1": "2001:db8::/32,2001:db8::1",
	} {
		got, err := SourceAddresses(in)
		if err != nil || got != want {
			t.Errorf("SourceAddresses(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"office", "10.0.0.0/33", "10.0.0.1 10.0.0.2"} {
		if _, err := SourceAddresses(in); err == nil {
			t.Errorf("SourceAddresses(%q) took a list no server can read", in)
		}
	}
}

func TestSignUserCertificate(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(
		ca,
		newTestKey(t),
		[]string{"user-123"},
		"nokku:login:user:alice:user-123",
		0,
		ssh.UserCert,
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
	// The same set for every CA, a host decides what a session may do.
	if !maps.Equal(cert.Permissions.Extensions, userExtensions) {
		t.Errorf("extensions = %v, want %v", cert.Permissions.Extensions, userExtensions)
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
		[]string{"target-123"},
		"nokku:provision:daemon:d:d",
		0,
		ssh.HostCert,
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
	cert, err := SignCertificate(ca, newTestKey(t), []string{"u"}, "k", -time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v := validity(cert); v < 24*time.Hour {
		t.Errorf("negative TTL should fall back to default, got %v", v)
	}

	// Over-max TTL falls back to the default
	cert, err = SignCertificate(ca, newTestKey(t), []string{"u"}, "k", 1000*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v := validity(cert); v > 25*time.Hour {
		t.Errorf("over-max TTL should fall back to default, got %v", v)
	}

	// In-bounds TTL is honored
	cert, err = SignCertificate(ca, newTestKey(t), []string{"u"}, "k", 2*time.Hour, 0)
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
	if _, err := SignCertificate(ca, rsaPub, []string{"u"}, "k", 0, 0); err == nil {
		t.Error("expected RSA key to be rejected by ED25519-only policy")
	}
}

// A certificate without principals is valid for every account, and OpenSSH reads at most 256.
func TestSignCertificatePrincipalCount(t *testing.T) {
	ca := newTestCA(t)
	if _, err := SignCertificate(ca, newTestKey(t), nil, "k", 0, ssh.UserCert); err == nil {
		t.Error("signed a certificate without principals")
	}
	if _, err := SignCertificate(ca, newTestKey(t), make([]string, maxPrincipals+1), "k", 0, ssh.UserCert); err == nil {
		t.Error("signed a certificate with more principals than OpenSSH reads")
	}
}

func TestLoginPrincipal(t *testing.T) {
	if got := LoginPrincipal("subject", "target", "root"); got != "subject@target:root" {
		t.Errorf("LoginPrincipal = %q", got)
	}
}

func TestParseLoginPrincipal(t *testing.T) {
	subject := "0192d6a0-7c1e-7c3a-8f3b-6f2a9f0b1c2d"
	target := "0192d6a0-7c1e-7c3a-8f3b-6f2a9f0b1c2e"
	got, ok := ParseLoginPrincipal(LoginPrincipal(subject, target, "deploy"))
	if !ok || got != (Principal{SubjectID: subject, TargetID: target, Username: "deploy"}) {
		t.Errorf("ParseLoginPrincipal = %+v, %v", got, ok)
	}
	for _, bad := range []string{
		"", "deploy", subject + "@" + target, subject + "@" + target + ":",
		"root@" + target + ":deploy", subject + "@host:deploy",
	} {
		if _, ok := ParseLoginPrincipal(bad); ok {
			t.Errorf("ParseLoginPrincipal(%q) accepted", bad)
		}
	}
}
