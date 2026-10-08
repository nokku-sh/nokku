package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

// crypto/rand never fails, it stops the program when the system has no
// randomness to give. So nothing here returns an error.

func RandomString(size int) string {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
