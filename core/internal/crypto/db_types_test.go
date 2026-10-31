package crypto

import (
	"database/sql/driver"
	"testing"
)

// The stored form is lowercase hex of the sha256 digest. Any change silently invalidates stored tokens.
func TestHashToken_Digest(t *testing.T) {
	hash := HashToken("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if string(hash) != want {
		t.Errorf("HashToken(abc) = %q, want %q", hash, want)
	}
}

func TestHashedToken_ScanAndValue(t *testing.T) {
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
