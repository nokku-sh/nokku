package crypto

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"testing"
)

// resetRuntime clears the package-global encryptor so tests stay
// order-independent.
func resetRuntime(t *testing.T) {
	t.Helper()
	encryptor.Store(nil)
}

// testCipher marks its output, so a foreign blob fails to decrypt.
type testCipher struct{}

func (testCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return append([]byte("enc:"), plaintext...), nil
}

func (testCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, ok := bytes.CutPrefix(ciphertext, []byte("enc:"))
	if !ok {
		return nil, errors.New("not a ciphertext")
	}
	return plaintext, nil
}

// TestHashToken_Digest pins the stored representation to lowercase hex of
// the sha256 digest. Any change silently invalidates stored tokens.
func TestHashToken_Digest(t *testing.T) {
	hash := HashToken("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if string(hash) != want {
		t.Errorf("HashToken(abc) = %q, want %q", hash, want)
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

	if err := SetEncryptor(testCipher{}); err != nil {
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

	cipher := testCipher{}
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

	_ = SetEncryptor(testCipher{})

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
