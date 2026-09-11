package crypto

import (
	"database/sql/driver"
	"strings"
	"testing"
)

// resetRuntime clears the package-global encryptor so tests stay
// order-independent.
func resetRuntime(t *testing.T) {
	t.Helper()
	runtimeMu.Lock()
	runtime = primitives{}
	runtimeMu.Unlock()
}

func TestHashedToken_Verify(t *testing.T) {
	resetRuntime(t)

	hash, err := HashToken("nkd_abc_secret")
	if err != nil {
		t.Fatal(err)
	}
	if !hash.Verify("nkd_abc_secret") {
		t.Error("Verify() with correct token: want true")
	}
	if hash.Verify("nkd_abc_wrong") {
		t.Error("Verify() with wrong token: want false")
	}
	if hash.Hash() != string(hash) {
		t.Error("Hash() should return the raw digest")
	}
}

// TestHashToken_Digest pins the stored representation to lowercase hex of
// the sha256 digest. Any change silently invalidates stored tokens.
func TestHashToken_Digest(t *testing.T) {
	hash, err := HashToken("abc")
	if err != nil {
		t.Fatal(err)
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if string(hash) != want {
		t.Errorf("HashToken(abc) = %q, want %q", hash, want)
	}
}

func TestHashedToken_Verify_MalformedDigests(t *testing.T) {
	tests := []struct {
		name   string
		digest string
	}{
		{"empty", ""},
		{"not hex", "zzzz"},
		{"short hex", "abc"},
		{"valid hex wrong length", strings.Repeat("ab", 31)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if HashedToken(tt.digest).Verify("secret") {
				t.Errorf("Verify(%q): want false", tt.digest)
			}
		})
	}
}

func TestHashedToken_ScanAndValue(t *testing.T) {
	resetRuntime(t)

	var h HashedToken
	if err := h.Scan(nil); err != nil {
		t.Fatal(err)
	}
	if !h.IsZero() {
		t.Error("Scan(nil) should zero the value")
	}

	h = "digest"
	v, err := h.Value()
	if err != nil {
		t.Fatal(err)
	}
	if v != driver.Value("digest") {
		t.Errorf("Value() = %v, want digest", v)
	}
}

func TestEncryptedBytes_RoundTrip(t *testing.T) {
	resetRuntime(t)

	cipher, err := NewSecretbox([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if err := SetEncryptor(cipher); err != nil {
		t.Fatal(err)
	}

	raw := []byte("private key material")
	e := EncryptedBytes(raw)

	v, err := e.Value()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, ok := v.([]byte)
	if !ok {
		t.Fatalf("Value() type = %T, want []byte", v)
	}
	if string(encrypted) == string(raw) {
		t.Error("Value() did not encrypt")
	}

	var scanned EncryptedBytes
	if err := scanned.Scan(encrypted); err != nil {
		t.Fatal(err)
	}
	if string(scanned) != string(raw) {
		t.Errorf("Scan() = %q, want %q", scanned, raw)
	}
	if got := string(scanned.Bytes()); got != string(raw) {
		t.Errorf("Bytes() = %q, want %q", got, raw)
	}
}

func TestEncryptedBytes_ScanCases(t *testing.T) {
	resetRuntime(t)

	cipher, _ := NewSecretbox([]byte("0123456789abcdef0123456789abcdef"))
	_ = SetEncryptor(cipher)

	var e EncryptedBytes
	if err := e.Scan(nil); err != nil {
		t.Fatal(err)
	}
	if e != nil {
		t.Error("Scan(nil) should set nil")
	}

	enc, err := cipher.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	if err := e.Scan(string(enc)); err != nil {
		t.Errorf("Scan(string) error: %v", err)
	}
	if string(e) != "payload" {
		t.Errorf("Scan(string) = %q, want payload", e)
	}

	if err := e.Scan(42); err == nil {
		t.Error("Scan(int): want error")
	}
	if err := e.Scan([]byte("garbage")); err == nil {
		t.Error("Scan(garbage): want error")
	}
}

func TestEncryptedBytes_EmptyValueIsNil(t *testing.T) {
	resetRuntime(t)

	cipher, _ := NewSecretbox([]byte("0123456789abcdef0123456789abcdef"))
	_ = SetEncryptor(cipher)

	e := EncryptedBytes{}
	v, err := e.Value()
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Errorf("Value() = %v, want nil", v)
	}
}

func TestEncryptedBytes_WithoutEncryptor(t *testing.T) {
	resetRuntime(t)

	e := EncryptedBytes("x")
	if _, err := e.Value(); err == nil {
		t.Error("Value() without encryptor: want error")
	}
	if err := e.Scan([]byte("y")); err == nil {
		t.Error("Scan() without encryptor: want error")
	}
}

func TestRuntimeSetters(t *testing.T) {
	resetRuntime(t)

	if err := SetEncryptor(nil); err == nil {
		t.Error("SetEncryptor(nil): want error")
	}
	if _, err := Encryptor(); err == nil {
		t.Error("Encryptor() uninitialized: want error")
	}
}
