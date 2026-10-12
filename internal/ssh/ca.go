package ssh

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log/slog"
	"slices"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// Keypair holds the effective values after defaults and clamping.
type Keypair struct {
	Private any
	Public  any
	Type    nokkuv1.CertificateKeyType
	Bits    int32
}

// GenerateKey defaults to ED25519 and clamps bits to supported sizes.
func GenerateKey(
	keyType nokkuv1.CertificateKeyType,
	keyBits int32,
) (*Keypair, error) {
	switch keyType {
	case nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA:
		if !slices.Contains([]int{2048, 3072, 4096}, int(keyBits)) {
			keyBits = 2048
		}
		priv, err := rsa.GenerateKey(rand.Reader, int(keyBits))
		if err != nil {
			return nil, err
		}
		return &Keypair{Private: priv, Public: &priv.PublicKey, Type: keyType, Bits: keyBits}, nil

	case nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ECDSA:
		var curve elliptic.Curve
		switch keyBits {
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			if keyBits != 0 && keyBits != 256 {
				slog.Warn("invalid ecdsa key bits, using P-256", "bits", keyBits)
			}
			keyBits = 256
			curve = elliptic.P256()
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		return &Keypair{Private: priv, Public: &priv.PublicKey, Type: keyType, Bits: keyBits}, nil

	case nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519:
		fallthrough
	case nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_UNSPECIFIED:
		fallthrough
	default:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &Keypair{
			Private: priv,
			Public:  pub,
			Type:    nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519,
		}, nil
	}
}

// NewCA makes the key and returns a CA with the settings every new one starts with. They are stated here and
// nowhere else. The caller names the CA and overrides what a request asks for. No lifetime means a year, the
// protos keep a requested one between a month and five years.
func NewCA(
	keyType nokkuv1.CertificateKeyType,
	keyBits int32,
	lifetime time.Duration,
) (*db.CreateCAParams, error) {
	kp, err := GenerateKey(keyType, keyBits)
	if err != nil {
		return nil, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(kp.Private)
	if err != nil {
		return nil, err
	}

	pubStr, err := MarshalPubKey(kp.Public)
	if err != nil {
		return nil, err
	}

	lifetime = cmp.Or(lifetime, 365*24*time.Hour)
	now := time.Now()
	return &db.CreateCAParams{
		PrivateKey:          crypto.EncryptedBytes(privDER),
		PublicKey:           pubStr,
		NotBefore:           now,
		NotAfter:            now.Add(lifetime),
		KeyType:             kp.Type,
		KeyBits:             kp.Bits,
		Lifetime:            lifetime,
		UserDefaultTtl:      5 * 24 * time.Hour,
		UserMaxTtl:          7 * 24 * time.Hour,
		UserCriticalOptions: []byte(`{}`),
		HostDefaultTtl:      90 * 24 * time.Hour,
		HostMaxTtl:          180 * 24 * time.Hour,
		AllowedKeyTypes: []nokkuv1.CertificateKeyType{
			nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_RSA,
			nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ECDSA,
			nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519,
		},
	}, nil
}
