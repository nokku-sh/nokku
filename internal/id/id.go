// Package id derives a stable machine fingerprint, the password that wraps
// software signing keys at rest. It never leaves the machine.
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

// MachineID fails on a failed read, a guess would change every wrapped key.
func MachineID() (string, error) {
	// Readers return "" for no ID, and an error only for a failed read.
	id, readErr := machineID()
	host, _ := os.Hostname()
	raw, err := rawMachineID(id, readErr, host)
	if err != nil {
		return "", err
	}
	return deriveMachineID(raw), nil
}

// The raw ID or hostname is never exposed, only this derived value.
func deriveMachineID(raw string) string {
	mac := hmac.New(sha256.New, machineIDKey)
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// The hostname stands in for a missing or placeholder ID, not a failed read.
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

// Placeholders are not unique, so they never derive a key.
func isBlankMachineID(id string) bool {
	return id == "uninitialized" || strings.Trim(id, "0-") == ""
}
