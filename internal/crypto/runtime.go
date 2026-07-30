package crypto

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrEncryptorMissing      = errors.New("encryptor not initialized")
	ErrPasswordHasherMissing = errors.New("password hasher not initialized")
	ErrTokenHasherMissing    = errors.New("token hasher not initialized")

	runtimeMu sync.RWMutex
	runtime   primitives
)

type primitives struct {
	encryptor      Cipher
	passwordHasher Verifier
	tokenHasher    Verifier
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

func SetPasswordHasher(hasher Verifier) error {
	if hasher == nil {
		return ErrPasswordHasherMissing
	}
	runtimeMu.Lock()
	runtime.passwordHasher = hasher
	runtimeMu.Unlock()
	return nil
}

func SetTokenHasher(hasher Verifier) error {
	if hasher == nil {
		return ErrTokenHasherMissing
	}
	runtimeMu.Lock()
	runtime.tokenHasher = hasher
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

func PasswordHasher() (Verifier, error) {
	runtimeMu.RLock()
	hasher := runtime.passwordHasher
	runtimeMu.RUnlock()
	if hasher == nil {
		return nil, ErrPasswordHasherMissing
	}
	return hasher, nil
}

func TokenHasher() (Verifier, error) {
	runtimeMu.RLock()
	hasher := runtime.tokenHasher
	runtimeMu.RUnlock()
	if hasher == nil {
		return nil, ErrTokenHasherMissing
	}
	return hasher, nil
}

func InitDefaultHashers() error {
	passwordHasher, err := NewHasher(Argon2ID)
	if err != nil {
		return fmt.Errorf("create password hasher: %w", err)
	}
	tokenHasher, err := NewHasher(SHA256)
	if err != nil {
		return fmt.Errorf("create token hasher: %w", err)
	}
	if err := SetPasswordHasher(passwordHasher); err != nil {
		return err
	}
	if err := SetTokenHasher(tokenHasher); err != nil {
		return err
	}
	return nil
}
