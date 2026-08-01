package crypto

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
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

func TestArgon2RoundTrip(t *testing.T) {
	hasher, err := NewHasher(Argon2ID)
	if err != nil {
		t.Fatal(err)
	}

	digest, err := hasher.Digest("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(digest, "$argon2id$") {
		t.Errorf("digest %q missing argon2id prefix", digest)
	}

	if !hasher.Verify("hunter2", digest) {
		t.Error("Verify() with correct secret: want true")
	}
	if hasher.Verify("hunter3", digest) {
		t.Error("Verify() with wrong secret: want false")
	}
}

// TestArgon2Verify_LowCostDigest exercises verify against a hand-built,
// low-cost digest so the test stays fast (m=1024 instead of 65536).
func TestArgon2Verify_LowCostDigest(t *testing.T) {
	hasher, _ := NewHasher(Argon2ID)

	salt := []byte("0123456789abcdef")
	computed := argon2.IDKey([]byte("secret"), salt, 1, 1024, 1, 32)
	digest := "$argon2id$v=19$m=1024,t=1,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(computed)

	if !hasher.Verify("secret", digest) {
		t.Error("Verify() against known digest: want true")
	}
	if hasher.Verify("wrong", digest) {
		t.Error("Verify() with wrong secret: want false")
	}
}

func TestArgon2Verify_MalformedDigests(t *testing.T) {
	hasher, _ := NewHasher(Argon2ID)

	salt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	hash := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))

	tests := []struct {
		name   string
		digest string
	}{
		{"empty", ""},
		{"too few parts", "$argon2id$v=19$"},
		{"wrong algorithm", "$bcrypt$v=19$m=1024,t=1,p=1$" + salt + "$" + hash},
		{"bad params segment", "$argon2id$v=19$m=notanumber,t=1,p=1$" + salt + "$" + hash},
		{"missing param", "$argon2id$v=19$m=1024,t=1$" + salt + "$" + hash},
		{"zero memory param", "$argon2id$v=19$m=0,t=1,p=1$" + salt + "$" + hash},
		{"zero threads param", "$argon2id$v=19$m=1024,t=1,p=0$" + salt + "$" + hash},
		{"threads overflow uint8", "$argon2id$v=19$m=1024,t=1,p=999$" + salt + "$" + hash},
		{"bad salt base64", "$argon2id$v=19$m=1024,t=1,p=1$!!!$" + hash},
		{"bad hash base64", "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "$!!!"},
		{"garbage", "not a digest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if hasher.Verify("secret", tt.digest) {
				t.Errorf("Verify(%q): want false", tt.digest)
			}
		})
	}
}

func TestArgon2Verify_TamperedHash(t *testing.T) {
	hasher, _ := NewHasher(Argon2ID)

	digest := "$argon2id$v=19$m=1024,t=1,p=1$" +
		base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef")) + "$" +
		base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))

	// Flip one char in the hash part so the computed hash cannot match.
	tampered := digest[:len(digest)-1] + "y"
	if hasher.Verify("secret", tampered) {
		t.Error("Verify() against tampered digest: want false")
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

func TestParseArgon2Params(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    argon2Params
		wantErr bool
	}{
		{"valid", "m=65536,t=2,p=4", argon2Params{memory: 65536, time: 2, threads: 4}, false},
		{
			"order independent",
			"t=1,p=2,m=1024",
			argon2Params{memory: 1024, time: 1, threads: 2},
			false,
		},
		{"missing key", "m=1024,1,p=1", argon2Params{}, true},
		{
			"unknown key ignored",
			"m=1024,t=1,p=1,x=99",
			argon2Params{memory: 1024, time: 1, threads: 1},
			false,
		},
		{"non-numeric value", "m=abc,t=1,p=1", argon2Params{}, true},
		{"missing memory", "t=1,p=1", argon2Params{}, true},
		{"missing time", "m=1024,p=1", argon2Params{}, true},
		{"missing threads", "m=1024,t=1", argon2Params{}, true},
		{"threads overflow", "m=1024,t=1,p=256", argon2Params{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgon2Params(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseArgon2Params(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("parseArgon2Params(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}
