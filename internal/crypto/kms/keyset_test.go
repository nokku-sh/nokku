package kms

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// fakeKEK stands in for a KMS KEK: it "wraps" by tagging the blob with its
// key byte, so unwrapping with a different KEK fails loudly.
type fakeKEK struct{ id byte }

var _ tink.AEAD = fakeKEK{}

func (f fakeKEK) Encrypt(plaintext, _ []byte) ([]byte, error) {
	return append([]byte{f.id}, plaintext...), nil
}

func (f fakeKEK) Decrypt(ciphertext, _ []byte) ([]byte, error) {
	if len(ciphertext) == 0 || ciphertext[0] != f.id {
		return nil, errors.New("wrong KEK")
	}
	return ciphertext[1:], nil
}

func TestWrapUnwrapRoundtrip(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("create keyset: %v", err)
	}

	data, err := wrap(handle, fakeKEK{id: 1})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	loaded, err := unwrap(data, fakeKEK{id: 1})
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}

	// The persisted bytes must be sufficient to reconstruct a working cipher.
	primitive, err := aead.New(loaded)
	if err != nil {
		t.Fatalf("create primitive: %v", err)
	}
	plaintext := []byte("ca private key")
	ciphertext, err := primitive.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := primitive.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestUnwrapWrongKEKFails(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("create keyset: %v", err)
	}
	data, err := wrap(handle, fakeKEK{id: 1})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	// A wrong KEK (e.g. misconfigured KMS_URI) must fail loudly at boot
	// instead of silently running with a broken encryptor.
	if _, err := unwrap(data, fakeKEK{id: 2}); err == nil {
		t.Fatal("expected unwrap with wrong KEK to fail")
	}
}

func TestUnwrapCorruptDataFails(t *testing.T) {
	if _, err := unwrap([]byte("not a keyset"), fakeKEK{id: 1}); err == nil {
		t.Fatal("expected unwrap of corrupt data to fail")
	}
}
