// Package id derives a stable machine fingerprint from the hardware machine
// ID, falling back to the hostname on a machine that has none. It is only the
// password that wraps software signing keys at rest, so it never leaves the
// machine. The value is HMAC'd, exposing a fixed-length derived key rather
// than the raw identifier.
package id

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// The key normalizes the identifier, it adds no secrecy.
var machineIDKey = []byte("machine-id")

// MachineID returns the machine's stable identity, derived from the machine
// ID, or from the hostname on a machine without one. It fails when the
// machine ID cannot be read right now or neither source exists, a guessed
// value would silently change every key wrapped with it.
func MachineID() (string, error) {
	// The platform readers return "" for a machine without an ID and an error only for a failed read.
	id, readErr := machineID()
	host, _ := os.Hostname()
	raw, err := rawMachineID(id, readErr, host)
	if err != nil {
		return "", err
	}
	return deriveMachineID(raw), nil
}

// The raw machine ID or hostname is never exposed, only a fixed-length derived value.
func deriveMachineID(raw string) string {
	mac := hmac.New(sha256.New, machineIDKey)
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// The hostname only stands in for an ID that is missing or a placeholder, never for one that failed to read.
func rawMachineID(id string, readErr error, host string) (string, error) {
	switch {
	case readErr != nil:
		return "", fmt.Errorf("id: read machine ID: %w", readErr)
	case !isBlankMachineID(id):
		return id, nil
	case host == "":
		return "", errors.New("id: this machine has no machine ID and no hostname")
	}
	return host, nil
}

// Placeholders (all zeros, dashed or not, or systemd's "uninitialized") are not unique, so they never derive a key.
func isBlankMachineID(id string) bool {
	return id == "uninitialized" || strings.Trim(id, "0-") == ""
}
