package state

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePrincipal(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"root", "deploy", "_svc", "john.doe", "John", "ec2-user", "host$", strings.Repeat("a", 32)} {
		require.NoError(t, validatePrincipal(name), name)
	}
	for _, name := range []string{"", ".", "..", "-rf", "0abc", "a/b", "a b", "üser", "a$b", strings.Repeat("a", 33)} {
		assert.Error(t, validatePrincipal(name), name)
	}
}

// An accepted name must always be safe as a path component.
func FuzzValidatePrincipal(f *testing.F) {
	f.Add("roxas")
	f.Add("..")
	f.Add("john.doe")
	f.Fuzz(func(t *testing.T, principal string) {
		if validatePrincipal(principal) != nil {
			return
		}
		if principal == "." || principal == ".." || strings.ContainsAny(principal, "/\x00") {
			t.Fatalf("validatePrincipal(%q) accepted an unsafe name", principal)
		}
	})
}
