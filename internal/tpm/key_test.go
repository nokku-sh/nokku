package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func openSimulator(t *testing.T) transport.TPMCloser {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("tpm simulator unavailable: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	return sim
}

// sharedTPM hands the simulator to several signers without closing it, so one
// test can open more than one identity against the same TPM. The simulator
// itself is closed when the test ends.
type sharedTPM struct{ transport.TPM }

func (sharedTPM) Close() error { return nil }

// simOpen returns a SignerOptions.OpenTPM backed by the simulator.
func simOpen(t *testing.T) func() (transport.TPMCloser, error) {
	sim := openSimulator(t)
	return func() (transport.TPMCloser, error) { return sharedTPM{sim}, nil }
}

func TestKeySign(t *testing.T) {
	sim := openSimulator(t)

	k, err := newTPMSigner(sharedTPM{sim}, []byte("test-key"))
	if err != nil {
		t.Fatalf("newTPMSigner: %v", err)
	}
	defer func() { _ = k.Close() }()

	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T, want *ecdsa.PublicKey", k.Public())
	}

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature verification failed")
	}

	// The key template pins SHA-256: other hashes must be rejected rather
	// than producing a signature under the wrong scheme.
	if _, err = k.Sign(rand.Reader, digest[:], crypto.SHA384); err == nil {
		t.Fatal("Sign with SHA-384 succeeded, want rejection")
	}
}

// TestKeyDeterministic verifies the same salt on the same TPM reproduces the
// same key pair without storing anything on disk.
func TestKeyDeterministic(t *testing.T) {
	sim := openSimulator(t)

	salt := []byte("test-key")
	k1, err := newTPMSigner(sharedTPM{sim}, salt)
	if err != nil {
		t.Fatalf("newTPMSigner: %v", err)
	}
	defer func() { _ = k1.Close() }()

	k2, err := newTPMSigner(sharedTPM{sim}, salt)
	if err != nil {
		t.Fatalf("recreate key: %v", err)
	}
	defer func() { _ = k2.Close() }()

	ec1 := k1.Public().(*ecdsa.PublicKey)
	ec2 := k2.Public().(*ecdsa.PublicKey)
	if !ec1.Equal(ec2) {
		t.Fatal("public key is not deterministic across reopenings")
	}
}

// TestKeySaltIsolation verifies distinct salts derive distinct key pairs, so
// the daemon, the CLI and the SSH host identity never collide on one TPM.
func TestKeySaltIsolation(t *testing.T) {
	sim := openSimulator(t)

	k1, err := newTPMSigner(sharedTPM{sim}, []byte("nokku-daemon"))
	if err != nil {
		t.Fatalf("newTPMSigner(daemon): %v", err)
	}
	defer func() { _ = k1.Close() }()

	k2, err := newTPMSigner(sharedTPM{sim}, []byte("nokku-cli"))
	if err != nil {
		t.Fatalf("newTPMSigner(cli): %v", err)
	}
	defer func() { _ = k2.Close() }()

	p1 := k1.Public().(*ecdsa.PublicKey)
	p2 := k2.Public().(*ecdsa.PublicKey)
	if p1.Equal(p2) {
		t.Fatal("distinct salts must derive distinct key pairs")
	}
}

// TestKeySSHSigner verifies the TPM key works as an SSH host key signer via
// x/crypto/ssh's [crypto.Signer] support.
func TestKeySSHSigner(t *testing.T) {
	sim := openSimulator(t)

	k, err := newTPMSigner(sharedTPM{sim}, []byte("nokku-host"))
	if err != nil {
		t.Fatalf("newTPMSigner: %v", err)
	}
	defer func() { _ = k.Close() }()

	sshSigner, err := ssh.NewSignerFromSigner(k)
	if err != nil {
		t.Fatalf("ssh signer: %v", err)
	}

	// Sign a handshake blob. The signature must verify against the key.
	blob := []byte("SSH handshake transcript")
	sig, err := sshSigner.Sign(rand.Reader, blob)
	if err != nil {
		t.Fatalf("ssh sign: %v", err)
	}
	if err = sshSigner.PublicKey().Verify(blob, sig); err != nil {
		t.Fatalf("ssh verify: %v", err)
	}

	// The public key must marshal into authorized_keys format.
	text := bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshSigner.PublicKey()))
	if !bytes.HasPrefix(text, []byte("ecdsa-sha2-nistp256 ")) {
		t.Fatalf("authorized key is %q, want ecdsa-sha2-nistp256", text)
	}
}
