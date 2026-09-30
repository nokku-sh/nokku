package iam

import (
	"strings"
	"testing"
)

func TestHashVerifyPassword(t *testing.T) {
	params := defaultPasswordParams()

	h, err := hashPassword("hunter2", params)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("hash is not PHC argon2id format: %q", h)
	}

	ok, err := verifyPassword("hunter2", h)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Error("correct password did not verify")
	}

	ok, err = verifyPassword("hunter3", h)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if ok {
		t.Error("wrong password verified")
	}
}

func TestNeedsRehash(t *testing.T) {
	params := defaultPasswordParams()

	h, err := hashPassword("hunter2", params)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if needsRehash(h, params) {
		t.Error("freshly hashed password needs no rehash")
	}

	changed := params
	changed.Time = params.Time + 1
	if !needsRehash(h, changed) {
		t.Error("changed params should trigger a rehash")
	}

	if !needsRehash("not-a-hash", params) {
		t.Error("garbage hash should trigger a rehash")
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"  Alice@Example.COM ": "alice@example.com", //nolint:gocritic // whitespace in the key is the case under test
		"plain@example.com":    "plain@example.com",
	}
	for in, want := range cases {
		if got := normalizeEmail(in); got != want {
			t.Errorf("normalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDummyBurn(t *testing.T) {
	// The dummy path must produce a hash and verify against it without
	// error, so unknown-email logins burn real argon2id work.
	m := newPasswordManager(&Service{}, passwordParams{})
	h := m.dummy()
	if h == "" {
		t.Fatal("dummy hash was not built")
	}
	ok, err := verifyPassword(dummyPassword, h)
	if err != nil || !ok {
		t.Fatalf("dummy hash does not verify: ok=%v err=%v", ok, err)
	}
}
