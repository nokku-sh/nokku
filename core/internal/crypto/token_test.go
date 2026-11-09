package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allKinds = []TokenKind{
	TokenSession, TokenCLI, TokenDaemon, TokenServiceAccount, TokenSCIM, TokenLogin,
	TokenEmailChange, TokenEmailRevert, TokenInvite, TokenEnroll, TokenDeviceCode, TokenLoopback,
}

func TestNewTokenRoundTrips(t *testing.T) {
	for _, kind := range allKinds {
		raw, hash := NewToken(kind)
		prefix := "nk_" + string(kind) + "_"
		require.True(t, strings.HasPrefix(raw, prefix), "%q does not start with %q", raw, prefix)
		assert.Equal(t, HashToken(raw), hash, "the hash is not of the plaintext")
		assert.True(t, checkToken(raw, kind), "%s does not pass its own check", kind)
		assert.True(t, checkToken(raw, TokenLogin, kind), "%s is refused among other kinds", kind)
	}
	first, _ := NewToken(TokenSession)
	second, _ := NewToken(TokenSession)
	assert.NotEqual(t, first, second)
}

// internal/nktoken tests the format, this is the choice among kinds.
func TestCheckTokenRefuses(t *testing.T) {
	raw, _ := NewToken(TokenServiceAccount)
	assert.False(t, checkToken(raw), "no kind takes nothing")
	assert.False(t, checkToken(raw, TokenSCIM, TokenSession), "a service account key passes as another kind")
	assert.False(t, checkToken(RandomString(32), TokenServiceAccount), "an old session passes")
}

func TestTokenHash(t *testing.T) {
	raw, want := NewToken(TokenInvite)
	hash, ok := TokenHash(raw, TokenLogin, TokenInvite)
	assert.True(t, ok, "a token of a listed kind is refused")
	assert.Equal(t, want, hash, "the hash is not of the plaintext")

	hash, ok = TokenHash(raw, TokenLogin)
	assert.False(t, ok, "a token of another kind passes")
	assert.True(t, hash.IsZero(), "a refused token still gets a hash")
}
