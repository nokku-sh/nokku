package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

// crypto/rand never fails, it stops the program when the system has no
// randomness to give. So nothing here returns an error.

func RandomString(size int) string {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// RandomSerial is 128 random bits, a certificate serial number.
func RandomSerial() *big.Int {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return new(big.Int).SetBytes(b)
}
