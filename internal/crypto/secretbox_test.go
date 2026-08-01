package crypto

import (
	"bytes"
	"testing"
)

func TestSecretbox_RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cipher, err := NewSecretbox(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("sensitive daemon config")
	encrypted, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Output must include the nonce prefix plus sealed box, and differ
	// from the plaintext.
	if len(encrypted) <= 24 {
		t.Errorf("ciphertext too short: %d", len(encrypted))
	}
	if bytes.Equal(encrypted[24:], plaintext) {
		t.Error("ciphertext looks unencrypted")
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestSecretbox_NonceUniqueness(t *testing.T) {
	cipher, err := NewSecretbox([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	first, err := cipher.Encrypt([]byte("same plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := cipher.Encrypt([]byte("same plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Error("two encryptions of the same plaintext produced identical ciphertexts")
	}
}

func TestSecretbox_WrongKey(t *testing.T) {
	a, _ := NewSecretbox([]byte("0123456789abcdef0123456789abcdef"))
	b, _ := NewSecretbox([]byte("ffffffffffffffffffffffffffffffff"))

	encrypted, err := a.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decrypt(encrypted); err == nil {
		t.Error("Decrypt() with wrong key: want error")
	}
}

func TestSecretbox_MalformedCiphertext(t *testing.T) {
	cipher, _ := NewSecretbox([]byte("0123456789abcdef0123456789abcdef"))

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"shorter than nonce", []byte("short")},
		{"exactly nonce length", make([]byte, 24)},
		{"nonce plus garbage", append(make([]byte, 24), []byte("garbage-garbage-garbage")...)},
		{"nonce plus truncated box", append(make([]byte, 24), make([]byte, 15)...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := cipher.Decrypt(tt.in); err == nil {
				t.Errorf("Decrypt(%q): want error", tt.in)
			}
		})
	}
}

func TestSecretbox_TamperedCiphertext(t *testing.T) {
	cipher, _ := NewSecretbox([]byte("0123456789abcdef0123456789abcdef"))

	encrypted, err := cipher.Encrypt([]byte("secret payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit inside the sealed box (past the nonce).
	tampered := bytes.Clone(encrypted)
	tampered[30] ^= 0x01

	if _, err := cipher.Decrypt(tampered); err == nil {
		t.Error("Decrypt() with tampered ciphertext: want error")
	}
}

func TestSecretbox_KeyDerivation(t *testing.T) {
	// Passphrases and non-32-byte secrets must work via HKDF.
	secrets := [][]byte{
		[]byte("short"),
		[]byte("a passphrase with spaces and unicode ü"),
		bytes.Repeat([]byte{'k'}, 64),
	}

	for _, secret := range secrets {
		cipher, err := NewSecretbox(secret)
		if err != nil {
			t.Fatalf("NewSecretbox(%q) error: %v", secret, err)
		}
		encrypted, err := cipher.Encrypt([]byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decrypt() error: %v", err)
		}
		if string(decrypted) != "payload" {
			t.Errorf("Decrypt() = %q, want payload", decrypted)
		}
	}
}

func TestSecretbox_EmptySecret(t *testing.T) {
	if _, err := NewSecretbox(nil); err == nil {
		t.Error("NewSecretbox(nil): want error")
	}
	if _, err := NewSecretbox([]byte{}); err == nil {
		t.Error("NewSecretbox(empty): want error")
	}
}

func TestSecretbox_DerivedKeyConsistency(t *testing.T) {
	// Same passphrase must yield an interchangeable cipher.
	a, _ := NewSecretbox([]byte("passphrase"))
	b, _ := NewSecretbox([]byte("passphrase"))

	encrypted, err := a.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := b.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() with independently derived key: %v", err)
	}
	if string(decrypted) != "payload" {
		t.Errorf("Decrypt() = %q, want payload", decrypted)
	}
}
