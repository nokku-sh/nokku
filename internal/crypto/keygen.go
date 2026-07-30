// Package crypto provides functions for generating cryptographic keys
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

var ErrGenerateRandom = errors.New("failed to generate random bytes")

// RandomBytes returns a random byte array of the specified size.
func RandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, ErrGenerateRandom
	}
	return bytes, nil
}

// RandomString returns a random string of the specified size.
func RandomString(size int) (string, error) {
	bytes, err := RandomBytes(size)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func RandomSuffix(length int) string {
	bytes := make([]byte, (length+1)/2)
	if _, err := rand.Read(bytes); err != nil {
		return "0000" // Fallback if crypto/rand fails (extremely rare)
	}
	return hex.EncodeToString(bytes)[:length]
}

// RandomSerial returns a random 128-bit certificate serial number.
func RandomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate random serial: %w", err)
	}
	return serial, nil
}
