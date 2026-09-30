// Package pki is the X.509 counterpart of internal/ssh.
package pki

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/ssh"
)

// NewCA returns ssh.CAInfo so both authority types share storage and rotation.
func NewCA(
	keyType nokkuv1.CertificateKeyType,
	keyBits int32,
	lifetime time.Duration,
) (*ssh.CAInfo, error) {
	kp, err := ssh.GenerateKey(keyType, keyBits)
	if err != nil {
		return nil, err
	}

	serial, err := crypto.RandomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiry := ssh.CAExpiry(now, lifetime)
	subject := pkix.Name{
		CommonName:   "Nokku X509 Root CA",
		Organization: []string{"Nokku"},
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     expiry,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // signs leaf certs only, no intermediates
		SubjectKeyId:          subjectKeyID(kp.Public),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, kp.Public, kp.Private)
	if err != nil {
		return nil, fmt.Errorf("failed to self-sign CA certificate: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(kp.Private)
	if err != nil {
		return nil, err
	}

	pubStr, err := ssh.MarshalPubKey(kp.Public)
	if err != nil {
		return nil, err
	}

	return &ssh.CAInfo{
		Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		PrivateKey:   crypto.EncryptedBytes(privDER),
		PublicKey:    pubStr,
		SerialNumber: serial.String(),
		Subject:      subject.String(),
		NotBefore:    template.NotBefore,
		NotAfter:     expiry,
		KeyType:      kp.Type,
		KeyBits:      kp.Bits,
	}, nil
}

func subjectKeyID(pub any) []byte {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(pubDER)
	return sum[:20]
}
