package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

func TestSignCertificate_WeakRSA(t *testing.T) {
	ca := newTestCA(t, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA, 2048)

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignCertificate(ca, newTestCSR(t, priv, "weak"), 0, 0); err == nil {
		t.Error("expected 1024-bit RSA key to be rejected")
	}
}

func TestSignCertificate_BadCA(t *testing.T) {
	ca := newTestCA(t, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := newTestCSR(t, priv, "x")

	badCert := *ca
	badCert.Certificate = "not pem"

	badKey := *ca
	badKey.PrivateKey = crypto.EncryptedBytes([]byte("garbage"))

	tests := []struct {
		name    string
		ca      *db.CertificateAuthority
		wantErr string
	}{
		{"bad CA certificate", &badCert, "CA certificate"},
		{"bad CA private key", &badKey, "CA private key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := SignCertificate(tt.ca, csr, 0, 0); err == nil ||
				!strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestBoundTTL_PKI(t *testing.T) {
	ca := newTestCA(t, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0)

	client := nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AUTH
	server := nokkuv1.SignX509CertificateRequest_X509_USAGE_SERVER_AUTH

	if got := boundTTL(ca, client, 0); got != ca.UserDefaultTtl {
		t.Errorf("client zero TTL = %v, want user default %v", got, ca.UserDefaultTtl)
	}
	if got := boundTTL(ca, client, 200*time.Hour); got != ca.UserDefaultTtl {
		t.Errorf("client over-max TTL = %v, want user default", got)
	}
	if got := boundTTL(ca, client, 2*time.Hour); got != 2*time.Hour {
		t.Errorf("client in-range TTL = %v, want 2h", got)
	}
	if got := boundTTL(ca, server, 0); got != ca.HostDefaultTtl {
		t.Errorf("server zero TTL = %v, want host default %v", got, ca.HostDefaultTtl)
	}
	if got := boundTTL(ca, server, 5000*time.Hour); got != ca.HostDefaultTtl {
		t.Errorf("server over-max TTL = %v, want host default", got)
	}
}

func TestExtKeyUsageFor(t *testing.T) {
	client := x509.ExtKeyUsageClientAuth
	server := x509.ExtKeyUsageServerAuth

	tests := []struct {
		name  string
		usage nokkuv1.SignX509CertificateRequest_X509Usage
		want  []x509.ExtKeyUsage
	}{
		{
			"unspecified",
			nokkuv1.SignX509CertificateRequest_X509_USAGE_UNSPECIFIED,
			[]x509.ExtKeyUsage{client},
		},
		{
			"client",
			nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AUTH,
			[]x509.ExtKeyUsage{client},
		},
		{
			"server",
			nokkuv1.SignX509CertificateRequest_X509_USAGE_SERVER_AUTH,
			[]x509.ExtKeyUsage{server},
		},
		{
			"both",
			nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AND_SERVER,
			[]x509.ExtKeyUsage{client, server},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extKeyUsageFor(tt.usage)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestKeyUsageFor(t *testing.T) {
	rsaPub, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyUsageFor(&rsaPub.PublicKey); got&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("RSA key missing key-encipherment usage")
	}

	_, edPub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyUsageFor(edPub); got != x509.KeyUsageDigitalSignature {
		t.Errorf("ed25519 usage = %v, want digital-signature only", got)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyUsageFor(&ecKey.PublicKey); got != x509.KeyUsageDigitalSignature {
		t.Errorf("ecdsa usage = %v, want digital-signature only", got)
	}
}

func TestSignCertificateEd25519(t *testing.T) {
	ca := newTestCA(t, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	certPEM, expiresAt, err := SignCertificate(
		ca,
		newTestCSR(t, priv, "my-service"),
		nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AUTH,
		0,
	)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	leaf := verifyLeaf(t, ca, certPEM)

	if leaf.Subject.CommonName != "my-service" {
		t.Errorf("unexpected CN: %s", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "svc.internal" {
		t.Errorf("SANs not honored: %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP SANs not honored: %v", leaf.IPAddresses)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://nokku.local/ns/default/sa/test" {
		t.Errorf("URI SANs not honored: %v", leaf.URIs)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("expected client-auth EKU, got %v", leaf.ExtKeyUsage)
	}
	if leaf.IsCA {
		t.Error("leaf must not be a CA")
	}
	// Default TTL (unspecified -> user default 24h, minus clock-skew tolerance)
	if d := time.Until(expiresAt); d > 24*time.Hour || d < 23*time.Hour {
		t.Errorf("expected ~24h TTL, got %v", d)
	}
}

func TestSignCertificateServerAuthUsesHostTTL(t *testing.T) {
	ca := newTestCA(t, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ECDSA, 256)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, expiresAt, err := SignCertificate(
		ca,
		newTestCSR(t, priv, "server"),
		nokkuv1.SignX509CertificateRequest_X509_USAGE_SERVER_AUTH,
		0,
	)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}
	// Host default TTL is 2160h (90 days)
	if d := time.Until(expiresAt); d > 2160*time.Hour || d < 2159*time.Hour {
		t.Errorf("expected ~2160h host TTL, got %v", d)
	}
}

func TestSignCertificateRSAGetsKeyEncipherment(t *testing.T) {
	ca := newTestCA(t, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA, 2048)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, _, err := SignCertificate(
		ca,
		newTestCSR(t, priv, "rsa-client"),
		nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AND_SERVER,
		12*time.Hour,
	)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	leaf := verifyLeaf(t, ca, certPEM)
	if leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("RSA leaf missing key-encipherment usage")
	}
	if len(leaf.ExtKeyUsage) != 2 {
		t.Errorf("expected client+server EKU, got %v", leaf.ExtKeyUsage)
	}
}

func TestSignCertificateRejectsBadInput(t *testing.T) {
	ca := newTestCA(t, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0)

	if _, _, err := SignCertificate(ca, "not pem", 0, 0); err == nil {
		t.Error("expected error for garbage CSR")
	}

	// CSR signed with a mismatched signature should fail CheckSignature
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	csrPEM := newTestCSR(t, priv, "tampered")
	block, _ := pem.Decode([]byte(csrPEM))
	block.Bytes[len(block.Bytes)-10] ^= 0xFF // corrupt the signature
	tampered := string(pem.EncodeToMemory(block))
	if _, _, err := SignCertificate(ca, tampered, 0, 0); err == nil {
		t.Error("expected error for tampered CSR signature")
	}
}

func TestSignCertificateRespectsAllowedKeyTypes(t *testing.T) {
	ca := newTestCA(t, nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0)
	ca.AllowedKeyTypes = []nokkuv1.CertificateKeyType{
		nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignCertificate(
		ca,
		newTestCSR(t, priv, "ecdsa-client"),
		0,
		0,
	); err == nil {
		t.Error("expected ECDSA key to be rejected by ED25519-only policy")
	}
}
