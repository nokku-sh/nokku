package crypto

import (
	"errors"
	"sync"
)

var (
	ErrEncryptorMissing = errors.New("encryptor not initialized")

	runtimeMu sync.RWMutex
	runtime   primitives
)

type primitives struct {
	encryptor Cipher
}

func SetEncryptor(enc Cipher) error {
	if enc == nil {
		return ErrEncryptorMissing
	}
	runtimeMu.Lock()
	runtime.encryptor = enc
	runtimeMu.Unlock()
	return nil
}

func Encryptor() (Cipher, error) {
	runtimeMu.RLock()
	enc := runtime.encryptor
	runtimeMu.RUnlock()
	if enc == nil {
		return nil, ErrEncryptorMissing
	}
	return enc, nil
}
