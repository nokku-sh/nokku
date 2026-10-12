package email

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifySyntax(t *testing.T) {
	for _, addr := range []string{"user@example.com", "first.last+tag@sub.example.co"} {
		require.NoError(t, Verify(t.Context(), addr, false), addr)
	}
	for _, addr := range []string{
		"",
		"no-at-sign",
		"@example.com",
		"user@",
		"Name <user@example.com>",
		"user@example.com, other@example.com",
		"user @example.com",
	} {
		require.ErrorIs(t, Verify(t.Context(), addr, false), errInvalidAddress, "%q", addr)
	}
}
