package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
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

// simOpen returns a SignerOptions.OpenTPM backed by sim.
func simOpen(sim transport.TPM) func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) { return sharedTPM{sim}, nil }
}

// clearTPM replaces the storage seed, as a TPM clear in the firmware setup does.
func clearTPM(t *testing.T, sim transport.TPM) {
	t.Helper()
	_, err := tpm2.Clear{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(nil)},
	}.Execute(sim)
	require.NoError(t, err)
}

func testKey(t *testing.T, sim transport.TPM) (*tpmSigner, *keyfile.TPMKey) {
	t.Helper()
	key, err := createTPMKey(sharedTPM{sim})
	require.NoError(t, err)
	s, err := newTPMSigner(sharedTPM{sim}, key)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s, key
}

func testPub(t *testing.T, s crypto.Signer) *ecdsa.PublicKey {
	t.Helper()
	pub, ok := s.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "Public() is %T, want *ecdsa.PublicKey", s.Public())
	return pub
}

func TestKeySign(t *testing.T) {
	k, _ := testKey(t, openSimulator(t))

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(testPub(t, k), digest[:], sig), "signature verification failed")

	// Callers sign SHA-256 only, another hash must fail rather than sign under a scheme nobody checks.
	_, err = k.Sign(rand.Reader, digest[:], crypto.SHA384)
	require.Error(t, err, "Sign with SHA-384 succeeded")
}

// Every key is random. A second identity on the same TPM, another user's for one, can never rebuild this one.
func TestKeysAreRandom(t *testing.T) {
	sim := openSimulator(t)
	k1, _ := testKey(t, sim)
	k2, _ := testKey(t, sim)
	assert.False(t, testPub(t, k1).Equal(k2.Public()), "two keys on one TPM must differ")
}

// The key file is all the state the key needs. Read back, it signs as the same key.
func TestKeyFileRoundTrip(t *testing.T) {
	sim := openSimulator(t)
	k, key := testKey(t, sim)

	var file bytes.Buffer
	require.NoError(t, keyfile.Encode(&file, key))
	assert.True(t, strings.HasPrefix(file.String(), "-----BEGIN TSS2 PRIVATE KEY-----"), "not a TSS2 key file")

	decoded, err := keyfile.Decode(file.Bytes())
	require.NoError(t, err)
	again, err := newTPMSigner(sharedTPM{sim}, decoded)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := again.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(testPub(t, k), digest[:], sig))
}

// A cleared TPM has another storage seed and refuses every key file it wrapped before.
func TestKeyFileAfterClear(t *testing.T) {
	sim := openSimulator(t)
	_, key := testKey(t, sim)
	clearTPM(t, sim)

	_, err := newTPMSigner(sharedTPM{sim}, key)
	require.ErrorIs(t, err, ErrIdentityChanged)
}

// A TPM reset drops the loaded key of a long-lived signer. The key file brings it back.
func TestKeySignRecoversALostHandle(t *testing.T) {
	sim := openSimulator(t)
	k, _ := testKey(t, sim)

	_, err := tpm2.FlushContext{FlushHandle: k.hnd.Handle}.Execute(sim)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(testPub(t, k), digest[:], sig))
}

// A clear while the signer runs leaves a key it cannot load again. That is a changed identity, not a retry.
func TestKeySignAfterClear(t *testing.T) {
	sim := openSimulator(t)
	k, _ := testKey(t, sim)
	clearTPM(t, sim)

	digest := sha256.Sum256([]byte("hello nokku"))
	_, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.ErrorIs(t, err, ErrIdentityChanged)
}

// TestKeySSHSigner verifies the TPM key works as an SSH host key signer via
// x/crypto/ssh's [crypto.Signer] support.
func TestKeySSHSigner(t *testing.T) {
	k, _ := testKey(t, openSimulator(t))

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
