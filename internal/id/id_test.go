package id

import (
	"regexp"
	"testing"
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
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBlankMachineID(tc.id); got != tc.blank {
				t.Fatalf("isBlankMachineID(%q) = %v, want %v", tc.id, got, tc.blank)
			}
		})
	}
}

// TestDeriveMachineID verifies the fingerprint is deterministic, a
// fixed-length hex digest, and does not contain the raw identifier.
func TestDeriveMachineID(t *testing.T) {
	raw := "3d6e2c41f0c94a8f9b1d77e2a0c4b5e6"

	a := deriveMachineID(raw)
	b := deriveMachineID(raw)
	if a != b {
		t.Fatal("deriveMachineID is not deterministic")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a) {
		t.Fatalf("deriveMachineID = %q, want 64 lowercase hex chars", a)
	}
	if a == raw {
		t.Fatal("derived fingerprint must not be the raw identifier")
	}

	// Distinct machines must derive distinct fingerprints.
	if deriveMachineID("other-machine") == a {
		t.Fatal("distinct raw identifiers derived the same fingerprint")
	}
}
