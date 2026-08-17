package crypto

import (
	"strings"
	"testing"
)

func TestSHA256RoundTrip(t *testing.T) {
	hasher, err := NewHasher(SHA256)
	if err != nil {
		t.Fatal(err)
	}

	digest, err := hasher.Digest("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Errorf("digest length = %d, want 64", len(digest))
	}

	if !hasher.Verify("correct horse battery staple", digest) {
		t.Error("Verify() with correct secret: want true")
	}
	if hasher.Verify("wrong secret", digest) {
		t.Error("Verify() with wrong secret: want false")
	}
}

func TestSHA256Verify_MalformedDigests(t *testing.T) {
	hasher, _ := NewHasher(SHA256)

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
			if hasher.Verify("secret", tt.digest) {
				t.Errorf("Verify(%q): want false", tt.digest)
			}
		})
	}
}

func TestNewHasher_UnknownAlgorithm(t *testing.T) {
	if _, err := NewHasher("md5"); err == nil {
		t.Error("NewHasher(md5): want error")
	}
	if _, err := NewHasher(""); err == nil {
		t.Error("NewHasher(\"\"): want error")
	}
}
