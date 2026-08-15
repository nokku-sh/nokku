package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// X25519KeySize is the size of an X25519 public key in bytes.
const X25519KeySize = 32

// ErrInvalidX25519Key is returned when a key is not a base64 X25519 public key.
var ErrInvalidX25519Key = errors.New("invalid X25519 public key")

// ParseX25519PublicKey decodes a base64 X25519 public key and checks its size.
func ParseX25519PublicKey(encoded string) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: not base64", ErrInvalidX25519Key)
	}
	if len(pub) != X25519KeySize {
		return nil, fmt.Errorf(
			"%w: got %d bytes, want %d",
			ErrInvalidX25519Key,
			len(pub),
			X25519KeySize,
		)
	}
	return pub, nil
}

// PublicKeyFingerprint is the first 16 hex chars of the key's SHA-256. It
// detects key changes and binds chunks to the key they were sealed with.
func PublicKeyFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
