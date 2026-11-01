package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Stored as lowercase sha256 hex. Any change invalidates every stored token.
func TestHashToken_Digest(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	assert.Equal(t, want, string(HashToken("abc")))
}

func TestHashedToken_ScanAndValue(t *testing.T) {
	var h HashedToken
	require.NoError(t, h.Scan(nil))
	assert.True(t, h.IsZero(), "Scan(nil) should zero the value")

	h = "digest"
	v, err := h.Value()
	require.NoError(t, err)
	assert.Equal(t, "digest", v)
}
