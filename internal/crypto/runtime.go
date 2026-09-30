package crypto

import (
	"errors"
	"sync"
)

var (
	errEncryptorMissing = errors.New("encryptor not initialized")

	runtimeMu sync.RWMutex
	runtime   primitives
)

type primitives struct {
	encryptor Cipher
}

func SetEncryptor(enc Cipher) error {
	if enc == nil {
		return errEncryptorMissing
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
		return nil, errEncryptorMissing
	}
	return enc, nil
}
