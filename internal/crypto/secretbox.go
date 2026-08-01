package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type Secretbox struct {
	key []byte
}

// NewSecretbox builds a Secretbox cipher. A 32-byte secret is used directly;
// any other length is derived to 32 bytes via HKDF-SHA256 with a fixed salt,
// so passphrases and shorter/longer secrets work unchanged.
func NewSecretbox(secret []byte) (*Secretbox, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret must not be empty")
	}
	if len(secret) == 32 {
		return &Secretbox{key: append([]byte(nil), secret...)}, nil
	}
	key, err := deriveKey(secret, 32)
	if err != nil {
		return nil, err
	}
	return &Secretbox{key: key}, nil
}

func deriveKey(secret []byte, outputKeyLen int) ([]byte, error) {
	return hkdf.Key(
		sha256.New,
		secret,
		[]byte("nokku-secretbox-v1"),
		"nokku",
		outputKeyLen,
	)
}

func (e *Secretbox) Encrypt(plaintext []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, errors.New("failed to generate nonce")
	}

	var key [32]byte
	copy(key[:], e.key)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	ciphertext := secretbox.Seal(nonce[:], plaintext, &nonce, &key)
	return ciphertext, nil
}

func (e *Secretbox) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 {
		return nil, errors.New("malformed ciphertext")
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	var key [32]byte
	copy(key[:], e.key)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	plaintext, ok := secretbox.Open(nil, ciphertext[24:], &nonce, &key)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}
