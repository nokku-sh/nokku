package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"
)

// DefaultPublicKey is the vendor's license-signing public key; the private
// key lives only in the license worker's environment.
const DefaultPublicKey = "Y1wP9BXsRVzKt+VEJ/6RWtNuXL88L3+hx+3ouLGdCjA="

// Verifier validates license keys offline with an Ed25519 public key.
type Verifier struct {
	pub ed25519.PublicKey
}

// NewVerifier returns a verifier for the given base64-encoded public key.
func NewVerifier(b64 string) (*Verifier, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return &Verifier{pub: ed25519.PublicKey(raw)}, nil
}

// DefaultVerifier uses the compiled-in vendor public key, overridable via
// NOKKU_LICENSE_PUBLIC_KEY (e.g. key rotation or tests).
func DefaultVerifier() (*Verifier, error) {
	if b64 := os.Getenv("NOKKU_LICENSE_PUBLIC_KEY"); b64 != "" {
		return NewVerifier(b64)
	}
	return NewVerifier(DefaultPublicKey)
}

// Verify parses and validates a license key. A valid but expired key returns
// (*Key, ErrExpired); anything else that fails returns (nil, error).
func (v *Verifier) Verify(key string) (*Key, error) {
	payload, sig, err := decodeKey(key)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(v.pub, payload, sig) {
		return nil, ErrInvalid
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalid
	}
	if claims.Version != int(version) || claims.Plan == "" {
		return nil, ErrInvalid
	}

	out := &Key{
		Key:   key,
		Plan:  claims.Plan,
		Email: claims.Email,
	}
	if claims.ExpiresAt > 0 {
		t := time.Unix(claims.ExpiresAt, 0)
		out.ExpiresAt = &t
		if time.Now().After(t) {
			return out, ErrExpired
		}
	}
	return out, nil
}
