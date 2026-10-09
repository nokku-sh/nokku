package crypto

import (
	"errors"
	"sync/atomic"
)

// Cipher encrypts what is stored at rest. The server sets one at startup.
type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

var errEncryptorMissing = errors.New("encryptor not initialized")

var encryptor atomic.Pointer[Cipher]

func SetEncryptor(enc Cipher) error {
	if enc == nil {
		return errEncryptorMissing
	}
	encryptor.Store(&enc)
	return nil
}

func Encryptor() (Cipher, error) {
	enc := encryptor.Load()
	if enc == nil {
		return nil, errEncryptorMissing
	}
	return *enc, nil
}
