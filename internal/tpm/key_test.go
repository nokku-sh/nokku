package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/google/go-tpm/tpm2"
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

func testKey(t *testing.T, sim transport.TPM, salt string) *tpmSigner {
	t.Helper()
	k, err := newTPMSigner(sharedTPM{sim}, []byte(salt))
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Close() })
	return k
}

func TestKeySign(t *testing.T) {
	k := testKey(t, openSimulator(t), "test-key")

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(k.pub, digest[:], sig), "signature verification failed")

	// The key template pins SHA-256: other hashes must be rejected rather
	// than producing a signature under the wrong scheme.
	_, err = k.Sign(rand.Reader, digest[:], crypto.SHA384)
	require.Error(t, err, "Sign with SHA-384 succeeded")
}

// TestKeyDeterministic verifies the same salt on the same TPM reproduces the
// same key pair without storing anything on disk.
func TestKeyDeterministic(t *testing.T) {
	sim := openSimulator(t)

	k1 := testKey(t, sim, "test-key")
	k2 := testKey(t, sim, "test-key")
	assert.True(t, k1.pub.Equal(k2.pub), "public key is not deterministic across reopenings")
}

// TestKeySaltIsolation verifies distinct salts derive distinct key pairs, so
// the daemon, the CLI and the SSH host identity never collide on one TPM.
func TestKeySaltIsolation(t *testing.T) {
	sim := openSimulator(t)

	k1 := testKey(t, sim, "nokku-daemon")
	k2 := testKey(t, sim, "nokku-cli")
	assert.False(t, k1.pub.Equal(k2.pub), "distinct salts must derive distinct key pairs")
}

// TestKeySSHSigner verifies the TPM key works as an SSH host key signer via
// x/crypto/ssh's [crypto.Signer] support.
func TestKeySSHSigner(t *testing.T) {
	k := testKey(t, openSimulator(t), "nokku-host")

	sshSigner, err := ssh.NewSignerFromSigner(k)
	require.NoError(t, err)

	// Sign a handshake blob. The signature must verify against the key.
	blob := []byte("SSH handshake transcript")
	sig, err := sshSigner.Sign(rand.Reader, blob)
	require.NoError(t, err)
	require.NoError(t, sshSigner.PublicKey().Verify(blob, sig))

	// The public key must marshal into authorized_keys format.
	text := string(ssh.MarshalAuthorizedKey(sshSigner.PublicKey()))
	assert.True(t, strings.HasPrefix(text, "ecdsa-sha2-nistp256 "), "authorized key is %q", text)
}

// A TPM reset drops the handle of a long-lived signer. The key is derived, so the signer gets it back.
func TestKeySignRecoversALostHandle(t *testing.T) {
	sim := openSimulator(t)
	k := testKey(t, sim, "test-key")

	_, err := tpm2.FlushContext{FlushHandle: k.hnd}.Execute(sim)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(k.pub, digest[:], sig))
}

// After a TPM clear the same salt derives another key. Signing with it would present an unregistered identity.
func TestKeySignRefusesAnotherKeyAfterReload(t *testing.T) {
	sim := openSimulator(t)
	k := testKey(t, sim, "test-key")

	_, err := tpm2.FlushContext{FlushHandle: k.hnd}.Execute(sim)
	require.NoError(t, err)
	k.salt = []byte("the seed changed")

	digest := sha256.Sum256([]byte("hello nokku"))
	_, err = k.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.ErrorIs(t, err, ErrIdentityChanged)
}
