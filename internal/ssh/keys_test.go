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

func TestParsePublicKey(t *testing.T) {
	line := keyLine(t, "x")

	if _, err := ParsePublicKey(line); err != nil {
		t.Fatalf("parse valid key: %v", err)
	}
	if _, err := ParsePublicKey("garbage"); err == nil {
		t.Fatal("parse garbage should fail")
	}
}
