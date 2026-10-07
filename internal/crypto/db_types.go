package crypto

import (
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
)

// EncryptedBytes encrypts at rest. String and MarshalJSON render "" so
// secrets never leak into logs or responses.
//
//nolint:recvcheck // Scan requires pointer receiver for sql.Scanner
type EncryptedBytes []byte

func (e EncryptedBytes) Bytes() []byte {
	out := make([]byte, len(e))
	copy(out, e)
	return out
}

func (e EncryptedBytes) Value() (driver.Value, error) {
	enc, err := Encryptor()
	if err != nil {
		return nil, err
	}
	if len(e) == 0 {
		return nil, nil
	}
	return enc.Encrypt(e)
}

func (e *EncryptedBytes) Scan(value any) error {
	if value == nil {
		*e = nil
		return nil
	}
	enc, err := Encryptor()
	if err != nil {
		return err
	}

	var encrypted []byte
	switch v := value.(type) {
	case []byte:
		encrypted = v
	case string:
		encrypted = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into EncryptedBytes", value)
	}
	if len(encrypted) == 0 {
		*e = nil
		return nil
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		return err
	}
	*e = decrypted
	return nil
}

func (e EncryptedBytes) String() string {
	return ""
}

func (e EncryptedBytes) MarshalJSON() ([]byte, error) {
	return []byte(`""`), nil
}

// HashedToken renders "" from String and MarshalJSON so hashes never leak.
//
//nolint:recvcheck // Scan requires pointer receiver for sql.Scanner
type HashedToken string

func HashToken(plaintext string) HashedToken {
	sum := sha256.Sum256([]byte(plaintext))
	return HashedToken(hex.EncodeToString(sum[:]))
}

func (h HashedToken) Hash() string {
	return string(h)
}

func (h HashedToken) IsZero() bool {
	return h == ""
}

func (h HashedToken) Value() (driver.Value, error) {
	if h == "" {
		return nil, nil
	}
	return string(h), nil
}

func (h *HashedToken) Scan(value any) error {
	if value == nil {
		*h = ""
		return nil
	}

	switch v := value.(type) {
	case string:
		*h = HashedToken(v)
	case []byte:
		*h = HashedToken(v)
	default:
		return fmt.Errorf("cannot scan %T into HashedToken", value)
	}

	return nil
}

func (h HashedToken) String() string {
	return ""
}

func (h HashedToken) MarshalJSON() ([]byte, error) {
	return []byte(`""`), nil
}
