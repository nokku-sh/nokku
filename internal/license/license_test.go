package license

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

// newTestVerifier returns a fresh test keypair's private key and a verifier
// for its public key. License issuance lives in the license worker, not the
// backend, so tests sign keys inline with the test keypair.
func newTestVerifier(t *testing.T) (ed25519.PrivateKey, *Verifier) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	verifier, err := NewVerifier(base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	return priv, verifier
}

// issue signs claims with a test private key, mirroring the worker's
// license.Sign, so verification can be exercised against freshly issued keys.
func issue(t *testing.T, priv ed25519.PrivateKey, email string, expiresAt time.Time) string {
	t.Helper()
	payload, err := json.Marshal(Claims{
		Version:   int(version),
		Plan:      "enterprise",
		Email:     email,
		ExpiresAt: expiresAt.UTC().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encodeKey(payload, ed25519.Sign(priv, payload))
}

func TestRoundTrip(t *testing.T) {
	priv, verifier := newTestVerifier(t)
	expires := time.Now().Add(24 * time.Hour)

	key := issue(t, priv, "ops@acme.io", expires)
	if !strings.HasPrefix(key, prefix) {
		t.Fatalf("key missing prefix: %q", key)
	}
	if len(key) < 20 {
		t.Fatalf("key suspiciously short: %q", key)
	}

	validated, err := verifier.Verify(key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if validated.Plan != "enterprise" || validated.Email != "ops@acme.io" {
		t.Fatalf("unexpected claims: %+v", validated)
	}
	if !validated.Valid() {
		t.Fatal("key should be valid")
	}
	if validated.ExpiresAt == nil || validated.ExpiresAt.Truncate(time.Second) != expires.Truncate(time.Second) {
		t.Fatalf("unexpected expiry: %v", validated.ExpiresAt)
	}
}

func TestExpired(t *testing.T) {
	priv, verifier := newTestVerifier(t)
	key := issue(t, priv, "a@b.io", time.Now().Add(-time.Hour))
	validated, err := verifier.Verify(key)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if validated == nil || validated.Valid() {
		t.Fatal("expired key must not grant access")
	}
}

func TestTampered(t *testing.T) {
	_, verifier := newTestVerifier(t)
	// Wrong key entirely.
	if _, err := verifier.Verify("NOKKU-AAAA-BBBB-CCCC-DDDD"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	// Signed by a different key.
	other, _ := newTestVerifier(t)
	key := issue(t, other, "a@b.io", time.Now().Add(time.Hour))
	if _, err := verifier.Verify(key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid for foreign signature, got %v", err)
	}
}

func TestManager(t *testing.T) {
	priv, verifier := newTestVerifier(t)
	key := issue(t, priv, "a@b.io", time.Now().Add(time.Hour))

	m := &Manager{verifier: verifier, key: key}
	if err := m.Validate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !m.Configured() || !m.Active() {
		t.Fatal("manager should be active")
	}

	empty := &Manager{verifier: verifier, key: ""}
	if err := empty.Validate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if empty.Active() {
		t.Fatal("empty key must be inactive")
	}
}
