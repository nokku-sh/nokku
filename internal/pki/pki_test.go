package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

func newTestCA(t *testing.T, keyType nokkuv1.CertificateKeyType, keyBits int32) *db.CertificateAuthority {
	t.Helper()

	info, err := NewCA(keyType, keyBits, 8760*time.Hour)
	if err != nil {
		t.Fatalf("NewCA failed: %v", err)
	}
	if len(info.Certificate) == 0 {
		t.Fatal("expected PEM root certificate in CAInfo.Certificate")
	}

	return &db.CertificateAuthority{
		Certificate:     string(info.Certificate),
		PrivateKey:      info.PrivateKey,
		KeyType:         info.KeyType,
		UserDefaultTtl:  24 * time.Hour,
		UserMaxTtl:      168 * time.Hour,
		HostDefaultTtl:  2160 * time.Hour,
		HostMaxTtl:      4320 * time.Hour,
		AllowedKeyTypes: []nokkuv1.CertificateKeyType{1, 2, 3},
	}
}

func newTestCSR(t *testing.T, priv any, cn string) string {
	t.Helper()

	uri, err := url.Parse("spiffe://nokku.local/ns/default/sa/test")
	if err != nil {
		t.Fatalf("failed to parse URI SAN: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn, Organization: []string{"acme"}},
		DNSNames:    []string{"svc.internal", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		URIs:        []*url.URL{uri},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func verifyLeaf(t *testing.T, ca *db.CertificateAuthority, certPEM []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("signed certificate is not valid PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse signed certificate: %v", err)
	}

	caBlock, _ := pem.Decode([]byte(ca.Certificate))
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     x509.NewCertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Fatal("leaf verified against empty root pool, expected failure")
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("leaf failed verification against CA: %v", err)
	}
	return leaf
}

func TestNewCASelfSigned(t *testing.T) {
	for _, kt := range []nokkuv1.CertificateKeyType{1, 2, 3} {
		info, err := NewCA(kt, 0, 8760*time.Hour)
		if err != nil {
			t.Fatalf("NewCA(%v) failed: %v", kt, err)
		}

		block, _ := pem.Decode(info.Certificate)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse CA cert: %v", err)
		}
		if !cert.IsCA {
			t.Error("CA cert is not a CA")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Error("CA cert missing cert-sign key usage")
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("CA cert self-signature invalid: %v", err)
		}
		if info.KeyType != kt {
			t.Errorf("expected key type %v, got %v", kt, info.KeyType)
		}
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
