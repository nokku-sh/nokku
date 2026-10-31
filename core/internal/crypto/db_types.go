package crypto

import (
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
)

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
