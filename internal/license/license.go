// Package license issues and validates on-premise license keys.
//
// A license is an Ed25519-signed payload (plan, email, expiry) encoded as a
// human-friendly NOKKU-XXXX-... string. The vendor signs with a private key
// kept in its own environment; instances verify offline against a public key
// compiled into the binary, so activation works air-gapped.
package license

import (
	"errors"
	"os"
	"time"

	"golang.org/x/exp/slog"
)

var (
	ErrInvalid = errors.New("invalid license key")
	ErrExpired = errors.New("license key expired")
)

type Claims struct {
	Version   int    `json:"v"`
	Plan      string `json:"plan"`
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
}

type Key struct {
	Key       string
	Plan      string
	Email     string
	ExpiresAt *time.Time
}

// New returns the validated instance license from the environment, or a
// zero-value Key when absent/invalid so callers can rely on Valid() == false
// without nil checks. It never returns a nil-key/nil-error pair.
func New() (*Key, error) {
	verifier, err := DefaultVerifier()
	if err != nil {
		return nil, err
	}

	key, ok := os.LookupEnv("NOKKU_LICENSE_KEY")
	if !ok {
		return &Key{}, nil
	}
	validated, err := verifier.Verify(key)
	if err != nil {
		slog.Warn("instance license is not valid", "error", err)
		return &Key{}, nil
	}
	return validated, nil
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
