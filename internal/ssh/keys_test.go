package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// keyLine generates an ed25519 authorized-key line with the given comment.
func keyLine(t *testing.T, comment string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	return line + " " + comment
}

func TestHostKeyMatches(t *testing.T) {
	line := keyLine(t, "host@example")

	if !HostKeyMatches(line, line) {
		t.Fatal("identical lines should match")
	}

	// Same key material, different comment and surrounding whitespace.
	base := strings.TrimSuffix(line, " host@example")
	if !HostKeyMatches(line, "  "+base+"  rotated  ") {
		t.Fatal("same key with different comments should match")
	}

	other := keyLine(t, "host@example")
	if HostKeyMatches(line, other) {
		t.Fatal("different keys should not match")
	}

	if HostKeyMatches(line, "not a key") {
		t.Fatal("unparseable submitted key should not match")
	}
	if HostKeyMatches("not a key", line) {
		t.Fatal("unparseable pinned key should not match")
	}
}

func TestParsePublicKey(t *testing.T) {
	line := keyLine(t, "x")

	if _, err := ParsePublicKey(line); err != nil {
		t.Fatalf("parse valid key: %v", err)
	}
	if _, err := ParsePublicKey("garbage"); err == nil {
		t.Fatal("parse garbage should fail")
	}
}
