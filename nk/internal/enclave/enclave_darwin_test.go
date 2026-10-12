//go:build darwin && cgo && enclave

package enclave

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/tpm"
)

// software runs the whole bridge with an in-memory CryptoKit key. CI runners
// are VMs without an enclave, so this is as far as an automated test gets.
var software = backend{create: true, software: true}

func TestBridgeSignsDigest(t *testing.T) {
	blob, err := software.Create()
	require.NoError(t, err)
	signer, err := software.Open(blob)
	require.NoError(t, err)
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "public key is %T", signer.Public())

	// The bridge must sign the digest it is given, not hash it again.
	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig), "signature does not verify against the digest")

	again, err := software.Open(blob)
	require.NoError(t, err)
	assert.True(t, pub.Equal(again.Public()), "the blob reopened as another key")
}

func TestBridgeRejectsBadInput(t *testing.T) {
	_, err := software.Open([]byte("not a key"))
	require.Error(t, err)
	_, err = software.Open(nil)
	require.Error(t, err)

	blob, err := software.Create()
	require.NoError(t, err)
	signer, err := software.Open(blob)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("hello nokku"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	require.Error(t, err, "SHA-384 must be refused")
	_, err = signer.Sign(rand.Reader, digest[:16], crypto.SHA256)
	require.Error(t, err, "a short digest must be refused")
}

func TestCreateNeedsOptIn(t *testing.T) {
	_, err := backend{}.Create()
	require.ErrorContains(t, err, envEnable)
}

// TestSignerOverBridge runs the bridge under tpm.NewSigner, the way nk uses
// it: create, self-test, persist the blob, reopen.
func TestSignerOverBridge(t *testing.T) {
	opts := tpm.SignerOptions{
		Salt:      []byte("test-signer"),
		StatePath: filepath.Join(t.TempDir(), "signer.json"),
		Enclave:   software,
	}
	s1, err := tpm.NewSigner(opts)
	require.NoError(t, err)
	require.Equal(t, tpm.MethodEnclave, s1.Method())

	s2, err := tpm.NewSigner(opts)
	require.NoError(t, err)
	assert.Equal(t, string(s1.PEM()), string(s2.PEM()), "the identity changed after reopening")
}

// TestEnclaveOnThisMachine reports what the hardware does. It only fails when
// an enclave claims to be available and then cannot sign.
func TestEnclaveOnThisMachine(t *testing.T) {
	if !Available() {
		t.Skip("no Secure Enclave on this machine")
	}
	hardware := backend{create: true}
	blob, err := hardware.Create()
	require.NoError(t, err)
	signer, err := hardware.Open(blob)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig))
}
