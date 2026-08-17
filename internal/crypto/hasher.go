package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Algorithm identifies a hashing algorithm.
type Algorithm string

const (
	// SHA256 is the fast hashing algorithm used for API tokens and other
	// high-entropy secrets.
	SHA256 Algorithm = "sha256"
)

// Verifier hashes and verifies secrets.
type Verifier interface {
	Digest(secret string) (string, error)
	Verify(secret, digest string) bool
}

// Hasher implements Verifier for a fixed algorithm.
type Hasher struct {
	algo Algorithm
}

func NewHasher(algo Algorithm) (*Hasher, error) {
	if algo != SHA256 {
		return nil, fmt.Errorf("%s is not a hashing algorithm", algo)
	}
	return &Hasher{algo: algo}, nil
}

func (h *Hasher) Digest(secret string) (string, error) {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:]), nil
}

func (h *Hasher) Verify(secret, digest string) bool {
	checksum := sha256.Sum256([]byte(secret))
	decoded, err := hex.DecodeString(digest)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(checksum[:], decoded) == 1
}
