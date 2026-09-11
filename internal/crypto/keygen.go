package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

var ErrGenerateRandom = errors.New("failed to generate random bytes")

func randomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, ErrGenerateRandom
	}
	return bytes, nil
}

func RandomString(size int) (string, error) {
	bytes, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// RandomSerial returns a random 128-bit certificate serial number.
func RandomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate random serial: %w", err)
	}
	return serial, nil
}
