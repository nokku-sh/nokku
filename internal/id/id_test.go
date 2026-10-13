package id

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsBlankMachineID verifies placeholder machine IDs written by systemd
// in containers and VMs are rejected: they are not unique, so they must
// never derive a signing key.
func TestIsBlankMachineID(t *testing.T) {
	cases := []struct {
		name  string
		id    string
		blank bool
	}{
		{"real id", "3d6e2c41f0c94a8f9b1d77e2a0c4b5e6", false},
		{"uninitialized", "uninitialized", true},
		{"all zeros", "00000000000000000000000000000000", true},
		{"partial zeros", "0000000000000000000000000abc0000", false},
		{"dashed zero uuid", "00000000-0000-0000-0000-000000000000", true},
		{"dashed uuid", "4c4c4544-0042-3510-8052-b4c04f4a3432", false},
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.blank, isBlankMachineID(tc.id))
		})
	}
}

// TestDeriveMachineID verifies the fingerprint is deterministic, a
// fixed-length hex digest, and does not contain the raw identifier.
func TestDeriveMachineID(t *testing.T) {
	raw := "3d6e2c41f0c94a8f9b1d77e2a0c4b5e6"

	a := deriveMachineID(raw)
	assert.Equal(t, a, deriveMachineID(raw), "deriveMachineID is not deterministic")
	assert.Regexp(t, `^[0-9a-f]{64}$`, a)
	assert.NotEqual(t, raw, a, "derived fingerprint must not be the raw identifier")
	assert.NotEqual(t, a, deriveMachineID("other-machine"), "distinct machines derived the same fingerprint")
}

func TestRawMachineID(t *testing.T) {
	const realID = "3d6e2c41f0c94a8f9b1d77e2a0c4b5e6"
	for name, tc := range map[string]struct {
		id, host, want string
	}{
		"the machine ID wins":                  {realID, "box", realID},
		"a machine ID needs no hostname":       {realID, "", realID},
		"no machine ID falls back to hostname": {"", "box", "box"},
		"a placeholder falls back to hostname": {"00000000-0000-0000-0000-000000000000", "box", "box"},
		"uninitialized falls back to hostname": {"uninitialized", "box", "box"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := rawMachineID(tc.id, nil, tc.host)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// A guessed value would wrap the key with something every such machine shares, or swap it on a bad day.
func TestRawMachineIDFailsInsteadOfGuessing(t *testing.T) {
	readFailed := errors.New("ioreg timed out")
	_, err := rawMachineID("", readFailed, "box")
	require.ErrorIs(t, err, readFailed, "a failed read was replaced by the hostname")

	_, err = rawMachineID("", nil, "")
	require.Error(t, err, "a machine without an ID and a hostname got a shared constant")
}

func TestMachineID(t *testing.T) {
	a, err := MachineID()
	require.NoError(t, err)
	b, err := MachineID()
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.Len(t, a, 64)
}
