// Package id derives a stable machine fingerprint from the hardware machine
// ID, falling back to the hostname. It is only the password that wraps
// software signing keys at rest, so it never leaves the machine. The value is
// HMAC'd, exposing a fixed-length derived key rather than the raw identifier.
package id

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// machineIDKey is the HMAC key for the machine fingerprint. It exists to
// normalize the identifier, not to add secrecy.
var machineIDKey = []byte("machine-id")

// MachineID returns the machine's stable identity, degrading to the hostname
// and then "unknown" when no machine ID is available.
func MachineID() string {
	return deriveMachineID(rawMachineID())
}

// deriveMachineID HMACs the raw identifier so the machine ID (or hostname)
// itself is never exposed, only a fixed-length derived value.
func deriveMachineID(raw string) string {
	mac := hmac.New(sha256.New, machineIDKey)
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// rawMachineID returns the platform machine ID, or the hostname when it is
// missing, unreadable, or a non-unique placeholder.
func rawMachineID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	raw, err := machineID()
	if err != nil || isBlankMachineID(raw) {
		return hostname
	}

	return raw
}

// isBlankMachineID reports whether id is a placeholder some platforms write
// when no real machine ID exists (all zeros, or systemd's "uninitialized" in
// containers and VMs). Such an ID is not unique, so it must never derive the
// signing key.
func isBlankMachineID(id string) bool {
	return id == "uninitialized" || strings.Trim(id, "0") == ""
}
