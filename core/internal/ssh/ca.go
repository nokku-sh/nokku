package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// NewCA makes the two keys of a CA and returns it with the settings every new one starts with. They are stated
// here and nowhere else. The caller names the CA and overrides what a request asks for.
func NewCA() (*db.CreateCAParams, error) {
	user, err := newKey()
	if err != nil {
		return nil, err
	}
	host, err := newKey()
	if err != nil {
		return nil, err
	}
	return &db.CreateCAParams{
		PrivateKey:     user.private,
		PublicKey:      user.public,
		HostPrivateKey: host.private,
		HostPublicKey:  host.public,
		// A work day. nk renews at half-life, and it is also how long people keep working while the core is down.
		UserDefaultTtl: 16 * time.Hour,
		UserMaxTtl:     7 * 24 * time.Hour,
		HostDefaultTtl: 90 * 24 * time.Hour,
		HostMaxTtl:     180 * 24 * time.Hour,
	}, nil
}

// caKey is an Ed25519 key, the private half PKCS#8 and encrypted at rest, the public half in authorized_keys form.
type caKey struct {
	private crypto.EncryptedBytes
	public  string
}

func newKey() (caKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return caKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return caKey{}, err
	}
	public, err := MarshalPubKey(pub)
	if err != nil {
		return caKey{}, err
	}
	return caKey{private: crypto.EncryptedBytes(der), public: public}, nil
}
