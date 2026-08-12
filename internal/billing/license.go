package billing

// A license is an Ed25519-signed payload (plan, email, expiry) encoded as a
// human-friendly NOKKU-XXXX-... string. The vendor signs with a private key
// kept in its own environment; instances verify offline against a public key
// compiled into the binary, so activation works air-gapped.

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"
)

const (
	prefix  = "NOKKU-" // lets the verifier reject non-keys without decoding.
	version = byte(1)  // key format version; bump when the payload encoding changes.
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

// NewLicense returns the validated instance license from the environment, or a
// zero-value Key when absent/invalid so callers can rely on Valid() == false
// without nil checks. It never returns a nil-key/nil-error pair.
func NewLicense() (*Key, error) {
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

func (k *Key) Valid() bool {
	if k == nil || k.Plan == "" {
		return false
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return false
	}
	return true
}

// encodeKey renders version + payload + signature as a dash-grouped base64 string.
func encodeKey(payload, sig []byte) string {
	data := make([]byte, 0, 1+len(payload)+len(sig))
	data = append(data, version)
	data = append(data, payload...)
	data = append(data, sig...)

	s := base64.RawStdEncoding.EncodeToString(data)

	var b strings.Builder
	b.Grow(len(prefix) + len(s) + len(s)/5)
	b.WriteString(prefix)
	for i := 0; i < len(s); i += 5 {
		if i > 0 {
			b.WriteByte('-')
		}
		end := min(i+5, len(s))
		b.WriteString(s[i:end])
	}
	return b.String()
}

func decodeKey(key string) (payload, sig []byte, err error) {
	enc, ok := strings.CutPrefix(key, prefix)
	if !ok {
		return nil, nil, ErrInvalid
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(enc, "-", ""))
	if err != nil || len(raw) < 1+ed25519.SignatureSize+1 {
		return nil, nil, ErrInvalid
	}
	if raw[0] != version {
		return nil, nil, ErrInvalid
	}
	sigLen := ed25519.SignatureSize
	return raw[1 : len(raw)-sigLen], raw[len(raw)-sigLen:], nil
}
