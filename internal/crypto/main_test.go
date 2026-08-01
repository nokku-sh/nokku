package crypto

import (
	"os"
	"testing"
)

// TestMain initializes fast (SHA256) hashers so token/password helpers work
// without the slow argon2 defaults; individual tests override as needed.
func TestMain(m *testing.M) {
	tokenHasher, err := NewHasher(SHA256)
	if err != nil {
		panic(err)
	}
	passwordHasher, err := NewHasher(SHA256)
	if err != nil {
		panic(err)
	}
	if err := SetTokenHasher(tokenHasher); err != nil {
		panic(err)
	}
	if err := SetPasswordHasher(passwordHasher); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
