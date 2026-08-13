package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

// SignCertificate signs a PEM-encoded PKCS#10 CSR with an X.509 certificate
// authority and returns the PEM-encoded leaf certificate and its expiry.
// TTL bounds follow the authority's usage: client certs use user TTLs, server
// certs host TTLs. SANs and subject come from the CSR. Key usage derives from
// X509Usage and the leaf key type.
func SignCertificate(
	ca *db.CertificateAuthority,
	csrPEM string,
	usage nokkuv1.SignX509CertificateRequest_X509Usage,
	ttl time.Duration,
) ([]byte, time.Time, error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := isAllowedKeyType(ca.AllowedKeyTypes, csr.PublicKey); err != nil {
		return nil, time.Time{}, err
	}

	caCert, err := parseCACertificate(ca.Certificate)
	if err != nil {
		return nil, time.Time{}, err
	}
	caKey, err := x509.ParsePKCS8PrivateKey(ca.PrivateKey.Bytes())
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	ttl = boundTTL(ca, usage, ttl)
	serial, err := crypto.RandomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}

	notAfter := time.Now().Add(ttl)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              keyUsageFor(csr.PublicKey),
		ExtKeyUsage:           extKeyUsageFor(usage),
		BasicConstraintsValid: true,
		SubjectKeyId:          subjectKeyID(csr.PublicKey),
		AuthorityKeyId:        caCert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to sign certificate: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), notAfter, nil
}

func boundTTL(
	ca *db.CertificateAuthority,
	usage nokkuv1.SignX509CertificateRequest_X509Usage,
	ttl time.Duration,
) time.Duration {
	defaultTTL, maxTTL := ca.UserDefaultTtl, ca.UserMaxTtl
	if usage == nokkuv1.SignX509CertificateRequest_X509_USAGE_SERVER_AUTH {
		defaultTTL, maxTTL = ca.HostDefaultTtl, ca.HostMaxTtl
	}
	if ttl <= 0 || ttl > maxTTL {
		return defaultTTL
	}
	return ttl
}

// extKeyUsageFor maps the requested usage to X.509 extended key usage.
// Unspecified defaults to client auth, the most common case (mTLS, kubectl,
// database clients).
func extKeyUsageFor(
	usage nokkuv1.SignX509CertificateRequest_X509Usage,
) []x509.ExtKeyUsage {
	switch usage {
	case nokkuv1.SignX509CertificateRequest_X509_USAGE_SERVER_AUTH:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AND_SERVER:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	case nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AUTH:
		fallthrough
	case nokkuv1.SignX509CertificateRequest_X509_USAGE_UNSPECIFIED:
		fallthrough
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
}

// keyUsageFor returns the leaf key usage. RSA also gets key encipherment
// for legacy TLS key transport.
func keyUsageFor(pub any) x509.KeyUsage {
	usage := x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		usage |= x509.KeyUsageKeyEncipherment
	}
	return usage
}

func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("invalid CSR: PEM decoding failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	return csr, nil
}

func parseCACertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("CA certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	return cert, nil
}

func isAllowedKeyType(allowed []nokkuv1.CertificateKeyType, pub any) error {
	if len(allowed) == 0 {
		return nil
	}

	var keyType nokkuv1.CertificateKeyType
	switch pub.(type) {
	case *rsa.PublicKey:
		keyType = nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA
	case *ecdsa.PublicKey:
		keyType = nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ECDSA
	case ed25519.PublicKey:
		keyType = nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}

	if !slices.Contains(allowed, keyType) {
		return fmt.Errorf(
			"public key type %q is not allowed by certificate authority policy",
			keyType.String(),
		)
	}

	if rsaPub, ok := pub.(*rsa.PublicKey); ok && rsaPub.Size()*8 < 2048 {
		return errors.New("weak key: RSA keys must be at least 2048 bits")
	}
	return nil
}
