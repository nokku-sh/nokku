package ssh

import (
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
)

type CAInfo struct {
	PrivateKey crypto.EncryptedBytes
	PublicKey  string
	NotBefore  time.Time
	NotAfter   time.Time
	KeyType    nokkuv1.CertificateKeyType
	KeyBits    int32
}

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

// CAExpiry clamps to 1 month..5 years, default 1 year.
func CAExpiry(now time.Time, lifetime time.Duration) time.Time {
	expiry := now.Add(lifetime)
	if expiry.Before(now.AddDate(0, 1, 0)) || expiry.After(now.AddDate(5, 0, 0)) {
		return now.AddDate(1, 0, 0)
	}
	return expiry
}

func NewCA(
	keyType nokkuv1.CertificateKeyType,
	keyBits int32,
	lifetime time.Duration,
) (*CAInfo, error) {
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

	now := time.Now()
	return &CAInfo{
		PrivateKey: crypto.EncryptedBytes(privDER),
		PublicKey:  pubStr,
		NotBefore:  now,
		NotAfter:   CAExpiry(now, lifetime),
		KeyType:    kp.Type,
		KeyBits:    kp.Bits,
	}, nil
}
