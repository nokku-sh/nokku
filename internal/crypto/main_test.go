package crypto

import (
	"os"
	"testing"
)

// TestMain initializes the fast SHA256 token hasher so token helpers work
// without any further setup.
func TestMain(m *testing.M) {
	tokenHasher, err := NewHasher(SHA256)
	if err != nil {
		panic(err)
	}
	if err := SetTokenHasher(tokenHasher); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
