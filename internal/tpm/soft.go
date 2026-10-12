package tpm

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/nokku-sh/nokku/internal/id"
)

// Software keys are wrapped at rest with a key derived from the machine's
// identity, so a copied state directory yields nothing usable on another
// machine. This stops stolen or cloned state, not root on the machine.
//
// The machine identity is public, so a slow KDF would protect nothing and the
// wrap key comes from a plain HKDF.

// softSigner is the software fallback: a plain ECDSA key in process memory,
// wrapped at rest with a key derived from the machine identity.
type softSigner struct {
	key *ecdsa.PrivateKey
	pem []byte
}

func (s *softSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

// Sign signs a SHA-256 digest with the software key.
func (s *softSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

func (s *softSigner) Method() string { return MethodSoft }

func (s *softSigner) PEM() []byte { return append([]byte(nil), s.pem...) }

func (s *softSigner) Close() error { return nil }

// openSoft loads the wrapped software key from st, or creates and persists a
// new one when st is nil. A key that can no longer be unwrapped (the machine
// identity changed) fails with ErrIdentityChanged, or is replaced when
// SignerOptions.Recreate is set.
func openSoft(opts SignerOptions, st *state) (Signer, error) {
	if st != nil && len(st.Salt) > 0 && len(st.Nonce) > 0 && len(st.Data) > 0 {
		key, err := unwrapSoftKey(st)
		if err == nil {
			return &softSigner{key: key, pem: []byte(st.PubKey)}, nil
		}
		if !opts.Recreate {
			return nil, fmt.Errorf(
				"%w: cannot unwrap the signing key (%w), re-enroll to create a new key",
				ErrIdentityChanged, err,
			)
		}
		slog.Warn("tpm: software signing key cannot be unwrapped, creating a new key", "error", err)
	}
	return createSoft(opts)
}

// createSoft generates a fresh software key, wraps it to the machine identity
// and persists it.
func createSoft(opts SignerOptions) (Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tpm: generate key: %w", err)
	}
	pubPEM, err := storeSoftKey(opts.StatePath, key)
	if err != nil {
		return nil, err
	}
	return &softSigner{key: key, pem: pubPEM}, nil
}

// storeSoftKey wraps key to the machine identity and persists it. It returns
// the PEM of the public half.
func storeSoftKey(path string, key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("tpm: marshal key: %w", err)
	}

	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err = rand.Read(salt); err != nil {
		return nil, fmt.Errorf("tpm: generate salt: %w", err)
	}
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("tpm: generate nonce: %w", err)
	}
	gcm, err := newSoftGCM(salt)
	if err != nil {
		return nil, err
	}

	pubPEM, err := pemEncodePublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	st := &state{
		Method: MethodSoft,
		PubKey: string(pubPEM),
		Salt:   salt,
		Nonce:  nonce,
		Data:   gcm.Seal(nil, nonce, der, nil),
	}
	if err = saveState(path, st); err != nil {
		return nil, err
	}
	return pubPEM, nil
}

// newSoftGCM builds the AEAD that wraps the software key. Its key derives
// from the machine fingerprint, which is public, so this stops a copied state
// file, not a local reader.
func newSoftGCM(salt []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(id.MachineID()), salt, "mon software key wrap", 32)
	if err != nil {
		return nil, fmt.Errorf("tpm: derive wrap key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tpm: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tpm: create gcm: %w", err)
	}
	return gcm, nil
}

func unwrapSoftKey(st *state) (*ecdsa.PrivateKey, error) {
	gcm, err := newSoftGCM(st.Salt)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, st.Nonce, st.Data, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"unwrap signing key (%w), the machine identity changed (e.g. after a reinstall or VM clone)",
			err,
		)
	}
	key, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not ECDSA")
	}
	return priv, nil
}
