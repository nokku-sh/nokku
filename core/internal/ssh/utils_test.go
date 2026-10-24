package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGetSigner(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := getSigner(der)
	if err != nil {
		t.Fatalf("getSigner() error: %v", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("signer is %s, want Ed25519", signer.PublicKey().Type())
	}
}

// The core stores CA keys as PKCS#8 DER and nothing else, so anything else is not one of its keys.
func TestGetSigner_RejectsOtherForms(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	openssh, err := ssh.MarshalPrivateKey(ed, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"nil":         nil,
		"garbage":     []byte("not a key"),
		"pkcs8 pem":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"openssh pem": pem.EncodeToMemory(openssh),
	} {
		if _, err := getSigner(raw); err == nil {
			t.Errorf("getSigner(%s): want error", name)
		}
	}
}

func TestMarshalPubKey_RoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	line, err := MarshalPubKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if line == "" {
		t.Fatal("MarshalPubKey() = empty")
	}

	// The output must parse back as an authorized key matching the original.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("output %q does not parse as authorized key: %v", line, err)
	}
	want, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if string(pub.Marshal()) != string(want.Marshal()) {
		t.Error("round-tripped key does not match original")
	}
}
