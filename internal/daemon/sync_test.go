package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidUsers(t *testing.T) {
	t.Parallel()
	got := validUsers([]string{
		"root", "john.doe", "_svc", "machine$",
		"", "1user", "bad name", `corp\john`, "john@corp", "-flag",
		"a23456789012345678901234567890123",
	})
	assert.Equal(t, []string{"root", "john.doe", "_svc", "machine$"}, got)
	assert.Empty(t, validUsers(nil))
}

func TestValidEndpoints(t *testing.T) {
	t.Parallel()
	got := validEndpoints([]string{"10.0.0.5:4022", "[fd00::1]:4022", "example.com:22", "10.0.0.5", ""})
	assert.Equal(t, []string{"10.0.0.5:4022", "[fd00::1]:4022"}, got)
	assert.Nil(t, validEndpoints([]string{"example.com:22"}), "nil keeps the stored endpoints")
	assert.Nil(t, validEndpoints(nil))
}
