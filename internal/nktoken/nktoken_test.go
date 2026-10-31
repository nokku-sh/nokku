package nktoken

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIsValid(t *testing.T) {
	for _, kind := range []string{"sess", "sa", "enroll"} {
		raw := New(kind)
		prefix := "nk_" + kind + "_"
		require.True(t, strings.HasPrefix(raw, prefix), "%q does not start with %q", raw, prefix)
		assert.Len(t, raw, len(prefix)+minRandomLen+checkLen)
		assert.True(t, Valid(raw, kind), "%s does not pass its own check", kind)
	}
	first, second := New("sess"), New("sess")
	assert.NotEqual(t, first, second)
}

// A later Go may return a longer [rand.Text], so the length is a minimum.
func TestValidTakesALongerRandomPart(t *testing.T) {
	longer := "nk_sa_" + strings.Repeat("a", minRandomLen+4)
	assert.True(t, Valid(longer+check(longer), "sa"), "a longer random part is refused")

	shorter := "nk_sa_" + strings.Repeat("a", minRandomLen-1)
	assert.False(t, Valid(shorter+check(shorter), "sa"), "a shorter random part passes")
}

func TestValidRefuses(t *testing.T) {
	raw := New("sa")
	random := len("nk_sa_")
	flipped := []byte(raw)
	flipped[random] = 'b'
	if raw[random] == 'b' {
		flipped[random] = 'c'
	}
	for name, bad := range map[string]string{
		"empty":            "",
		"prefix only":      "nk_sa_",
		"another kind":     "nk_scim_" + raw[random:],
		"truncated":        raw[:len(raw)-1],
		"one more":         raw + "0",
		"flipped char":     string(flipped),
		"capitals":         raw[:random] + strings.ToUpper(raw[random:len(raw)-checkLen]) + raw[len(raw)-checkLen:],
		"not base32":       raw[:random] + "-" + raw[random+1:],
		"older format":     "nk_sa_" + strings.Repeat("A", 43) + "000000",
		"old join token":   "0199f3a1-7c2e-7d4b-9a10-3f2c1b0e8d7a_" + strings.Repeat("a", 32),
		"no prefix":        strings.TrimPrefix(raw, "nk_"),
		"another checksum": raw[:len(raw)-checkLen] + "00000000",
	} {
		assert.False(t, Valid(bad, "sa"), "%s: %q passes", name, bad)
	}
}
