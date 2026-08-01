// Package license issues and validates on-premise license keys.
//
// A license is an Ed25519-signed payload (plan, email, expiry) encoded as a
// human-friendly NOKKU-XXXX-... string. The vendor signs with a private key
// kept in its own environment; instances verify offline against a public key
// compiled into the binary, so activation works air-gapped.
package license

import (
	"errors"
	"time"
)

var (
	ErrInvalid = errors.New("invalid license key")
	ErrExpired = errors.New("license key expired")
)

// Claims is the signed payload carried by a license key. Everything else
// (features, limits) is derived from Plan by the entitlement catalog, so a
// key never drifts from the code that enforces it. Field order must match
// the worker's license.Claims: the JSON bytes are part of the signed payload.
type Claims struct {
	Version   int    `json:"v"`
	Plan      string `json:"plan"`
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
}

// Key is the validated state of a license key.
type Key struct {
	Key       string
	Plan      string
	Email     string
	ExpiresAt *time.Time
}

// Valid reports whether the key currently grants access.
func (k *Key) Valid() bool {
	if k == nil || k.Plan == "" {
		return false
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return false
	}
	return true
}

// State reports whether the instance is currently licensed.
type State interface {
	Active() bool
}
