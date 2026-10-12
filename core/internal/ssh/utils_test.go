package ssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGetSigner(t *testing.T) {
	// PEM-encoded PKCS#8 RSA key (what tink/sshgen emits).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})

	// PKCS#1 PEM.
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	// EC PEM.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})

	// Raw OpenSSH private key.
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opensshPEM, err := ssh.MarshalPrivateKey(edKey, "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  []byte
	}{
		{"pkcs8 pem", rsaPEM},
		{"pkcs1 pem", pkcs1PEM},
		{"ec pem", ecPEM},
		{"openssh pem", pem.EncodeToMemory(opensshPEM)},
		{"raw der", rsaDER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := getSigner(tt.key)
			if err != nil {
				t.Fatalf("getSigner() error: %v", err)
			}
			if signer == nil {
				t.Fatal("getSigner() = nil")
			}
			if len(signer.PublicKey().Marshal()) == 0 {
				t.Error("signer has empty public key")
			}
		})
	}
}

func TestGetSigner_RejectsGarbage(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("not a key"), []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")} {
		if _, err := getSigner(raw); err == nil {
			t.Errorf("getSigner(%q): want error", raw)
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
