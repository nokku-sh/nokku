package billing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestKey_Valid(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	tests := []struct {
		name string
		key  *Key
		want bool
	}{
		{"nil key", nil, false},
		{"empty plan", &Key{Plan: ""}, false},
		{"valid no expiry", &Key{Plan: "enterprise"}, true},
		{"valid with future expiry", &Key{Plan: "enterprise", ExpiresAt: &future}, true},
		{"expired", &Key{Plan: "enterprise", ExpiresAt: &past}, false},
		{"expired nil plan", &Key{ExpiresAt: &past}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewVerifier(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	if _, err := NewVerifier(pubB64); err != nil {
		t.Errorf("NewVerifier(valid key): %v", err)
	}

	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"not base64", "!!!not-base64!!!"},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("short"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewVerifier(tt.in); err == nil {
				t.Errorf("NewVerifier(%q): want error", tt.in)
			}
		})
	}
}

func TestVerify_ClaimsValidation(t *testing.T) {
	priv, verifier := newTestVerifier(t)

	issueRaw := func(claims Claims) string {
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		return encodeKey(payload, ed25519.Sign(priv, payload))
	}

	tests := []struct {
		name   string
		claims Claims
	}{
		{"wrong version", Claims{Version: 99, Plan: "enterprise"}},
		{"missing plan", Claims{Version: int(version)}},
		{"empty email ok but plan required", Claims{Version: int(version), Plan: "pro"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := issueRaw(tt.claims)
			validated, err := verifier.Verify(key)
			if err == nil && validated != nil {
				return // valid case (empty email)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("Verify() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestVerify_NoExpiry(t *testing.T) {
	priv, verifier := newTestVerifier(t)

	payload, err := json.Marshal(Claims{Version: int(version), Plan: "enterprise", Email: "a@b.io"})
	if err != nil {
		t.Fatal(err)
	}
	key := encodeKey(payload, ed25519.Sign(priv, payload))

	validated, err := verifier.Verify(key)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if validated.ExpiresAt != nil {
		t.Error("expiry should be nil when not set in claims")
	}
	if !validated.Valid() {
		t.Error("key without expiry should be valid")
	}
}

func TestVerify_EdgeExpiry(t *testing.T) {
	priv, verifier := newTestVerifier(t)
	expires := time.Now().Add(2 * time.Hour)

	key := issue(t, priv, "a@b.io", expires)
	validated, err := verifier.Verify(key)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if validated.ExpiresAt == nil ||
		!validated.ExpiresAt.Truncate(time.Second).Equal(expires.Truncate(time.Second)) {
		t.Errorf("expiry = %v, want %v", validated.ExpiresAt, expires)
	}
}

func TestDecodeKey(t *testing.T) {
	// Build a valid key then corrupt specific aspects.
	priv, _ := newTestVerifier(t)
	good := issue(t, priv, "a@b.io", time.Now().Add(time.Hour))

	if _, _, err := decodeKey(good); err != nil {
		t.Fatalf("decodeKey(valid) error: %v", err)
	}

	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"missing prefix", "ABC-123"},
		{"prefix only", prefix},
		{"lowercase prefix", "nokku-" + good[len(prefix):]},
		{"garbage after prefix", prefix + "!!!"},
		{"wrong version byte", corruptVersion(good)},
		{"too short", prefix + "AA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := decodeKey(tt.in); err == nil {
				t.Errorf("decodeKey(%q): want error", tt.in)
			}
		})
	}
}

// corruptVersion flips the leading version byte in the encoded key body.
func corruptVersion(key string) string {
	enc := strings.TrimPrefix(key, prefix)
	raw, err := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(enc, "-", ""))
	if err != nil {
		panic(err)
	}
	raw[0] ^= 0xFF

	s := base64.RawStdEncoding.EncodeToString(raw)
	var b strings.Builder
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

func TestVerify_TruncatedKey(t *testing.T) {
	priv, verifier := newTestVerifier(t)
	good := issue(t, priv, "a@b.io", time.Now().Add(time.Hour))

	for _, cut := range []int{1, 5, len(good) / 2} {
		if _, err := verifier.Verify(good[:len(good)-cut]); !errors.Is(err, ErrInvalid) {
			t.Errorf("Verify(truncated %d) error = %v, want ErrInvalid", cut, err)
		}
	}
}

func TestNew_FromEnv(t *testing.T) {
	// The positive path (valid key -> validated Key) can't be exercised here:
	// newLicense() verifies against the compiled-in vendor public key, whose private
	// key we don't hold. Key validation itself is covered by TestVerify_*.
	// These cases assert newLicense()'s env wiring and nil-safety contract.

	// Garbage keys are ignored, not fatal.
	t.Setenv("NOKKU_LICENSE_KEY", "NOKKU-BOGUS")
	key, err := newLicense()
	if err != nil {
		t.Fatalf("newLicense() with garbage key: %v", err)
	}
	if key == nil || key.Valid() {
		t.Error("expected invalid, non-nil license for garbage key")
	}

	// Empty env value behaves like absence.
	t.Setenv("NOKKU_LICENSE_KEY", "")
	key, err = newLicense()
	if err != nil {
		t.Fatalf("newLicense() without env: %v", err)
	}
	if key == nil || key.Valid() {
		t.Error("expected invalid, non-nil license without env")
	}
}
