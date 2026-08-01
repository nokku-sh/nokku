package pki

import (
	"crypto/rand"
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

func newTestCA(
	t *testing.T,
	keyType nokkuv1.CertificateKeyType,
	keyBits int32,
) *db.CertificateAuthority {
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
