package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// EnsureSAMLSPKey returns the deployment's shared SAML SP keypair as PEM,
// generating and persisting it on first boot. One keypair serves every
// workspace: the SP certificate identifies Nokku itself to every IdP.
func EnsureSAMLSPKey(ctx context.Context, conn *db.Connection) (keyPEM, certPEM []byte, err error) {
	if row, err := conn.Q.GetSAMLSPKey(ctx); err == nil && row != nil {
		return row.PrivateKey.Bytes(), []byte(row.Certificate), nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nokku"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	keyPEM = pem.EncodeToMemory(
		&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
	)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := conn.Q.PutSAMLSPKey(ctx, &db.PutSAMLSPKeyParams{
		PrivateKey:  crypto.EncryptedBytes(keyPEM),
		Certificate: string(certPEM),
	}); err != nil {
		return nil, nil, err
	}
	return keyPEM, certPEM, nil
}
