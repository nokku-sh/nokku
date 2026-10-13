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

// softSigner keeps a plain key in memory. Its wrap at rest stops a copied state file, not root on the machine.
type softSigner struct {
	key *ecdsa.PrivateKey
}

func (s *softSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

// Sign signs a SHA-256 digest with the software key.
func (s *softSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

func (s *softSigner) Method() string { return MethodSoft }

func (s *softSigner) Close() error { return nil }

// A key that no longer unwraps (the machine identity changed, the state is incomplete) is a changed identity.
func openSoft(opts SignerOptions, st *state) (Signer, error) {
	// A machine ID that cannot be read right now is not a changed identity, so it never replaces the key.
	machine, err := id.MachineID()
	if err != nil {
		return nil, fmt.Errorf("tpm: %w", err)
	}
	if st == nil {
		return createSoft(opts, machine)
	}

	key, err := unwrapSoftKey(st, machine)
	if err == nil {
		return &softSigner{key: key}, nil
	}
	if !opts.Recreate {
		return nil, fmt.Errorf(
			"%w: cannot unwrap the signing key (%w), re-enroll to create a new key",
			ErrIdentityChanged, err,
		)
	}
	slog.Warn("tpm: software signing key cannot be unwrapped, creating a new key", "error", err)
	return createSoft(opts, machine)
}

func createSoft(opts SignerOptions, machine string) (Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tpm: generate key: %w", err)
	}
	if err = storeSoftKey(opts.StatePath, key, machine); err != nil {
		return nil, err
	}
	return &softSigner{key: key}, nil
}

func storeSoftKey(path string, key *ecdsa.PrivateKey, machine string) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("tpm: marshal key: %w", err)
	}

	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return fmt.Errorf("tpm: generate salt: %w", err)
	}
	gcm, err := newSoftGCM(machine, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return fmt.Errorf("tpm: generate nonce: %w", err)
	}

	pubPEM, err := pemEncodePublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	return saveState(path, &state{
		Method: MethodSoft,
		PubKey: string(pubPEM),
		Salt:   salt,
		Nonce:  nonce,
		Data:   gcm.Seal(nil, nonce, der, nil),
	})
}

// The machine fingerprint is public, so a slow KDF would protect nothing and a plain HKDF derives the wrap key.
func newSoftGCM(machine string, salt []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(machine), salt, "mon software key wrap", 32)
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

func unwrapSoftKey(st *state, machine string) (*ecdsa.PrivateKey, error) {
	gcm, err := newSoftGCM(machine, st.Salt)
	if err != nil {
		return nil, err
	}
	// Open panics on a nonce of another length.
	if len(st.Salt) == 0 || len(st.Data) == 0 || len(st.Nonce) != gcm.NonceSize() {
		return nil, errors.New("the signer state is incomplete")
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
