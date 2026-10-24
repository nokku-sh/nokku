package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testOpts(t *testing.T, open func() (transport.TPMCloser, error)) SignerOptions {
	t.Helper()
	return SignerOptions{
		StatePath: filepath.Join(t.TempDir(), "signer.json"),
		OpenTPM:   open,
	}
}

func newTestSigner(
	t *testing.T,
	open func() (transport.TPMCloser, error),
	mutate func(*SignerOptions),
) Signer {
	t.Helper()
	opts := testOpts(t, open)
	if mutate != nil {
		mutate(&opts)
	}
	s, err := NewSigner(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func pemOf(t *testing.T, s Signer) string {
	t.Helper()
	pubPEM, err := pemEncodePublicKey(s.Public())
	require.NoError(t, err)
	return string(pubPEM)
}

func TestSignerTPM(t *testing.T) {
	opts := testOpts(t, simOpen(openSimulator(t)))

	s1, err := NewSigner(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s1.Close() })
	pub1 := testPub(t, s1)
	assert.Equal(t, MethodTPM, s1.Method())

	// The key file in the state brings the same key back after a restart.
	s2, err := NewSigner(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })
	assert.True(t, pub1.Equal(s2.Public()), "the TPM key changed across restarts")

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := s2.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub1, digest[:], sig), "signature verification failed")
}

// Two state files on one TPM are two identities, the daemon's DPoP and host keys or two users' nk keys.
func TestSignerStateFilesAreSeparate(t *testing.T) {
	open := simOpen(openSimulator(t))

	a := newTestSigner(t, open, nil)
	b := newTestSigner(t, open, nil)
	assert.False(t, testPub(t, a).Equal(b.Public()), "two state files must hold two keys")
}

// TestSignerIdentityChanged verifies a key the TPM no longer loads fails with
// ErrIdentityChanged, unless Recreate is set.
func TestSignerIdentityChanged(t *testing.T) {
	sim := openSimulator(t)
	opts := testOpts(t, simOpen(sim))

	s, err := NewSigner(opts)
	require.NoError(t, err)
	before := pemOf(t, s)
	require.NoError(t, s.Close())
	clearTPM(t, sim)

	_, err = NewSigner(opts)
	require.ErrorIs(t, err, ErrIdentityChanged)

	// With Recreate the signer replaces the key and persists it.
	opts.Recreate = true
	s2, err := NewSigner(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })
	assert.NotEqual(t, before, pemOf(t, s2))

	st2, err := loadState(opts.StatePath)
	require.NoError(t, err)
	assert.Equal(t, pemOf(t, s2), st2.PubKey, "recovered identity was not persisted")
}

// A TPM state without a key file, as the derived keys of older builds left it, is a changed identity.
func TestSignerTPMStateWithoutKeyFile(t *testing.T) {
	opts := testOpts(t, simOpen(openSimulator(t)))
	require.NoError(t, saveState(opts.StatePath, &state{Method: MethodTPM, PubKey: "pem"}))

	_, err := NewSigner(opts)
	require.ErrorIs(t, err, ErrIdentityChanged)

	opts.Recreate = true
	s, err := NewSigner(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	assert.Equal(t, MethodTPM, s.Method())
}

func TestSignerRequiresPath(t *testing.T) {
	_, err := NewSigner(SignerOptions{})
	require.Error(t, err, "NewSigner without state path succeeded")
}

func TestSoftSignerRoundTrip(t *testing.T) {
	opts := SignerOptions{StatePath: filepath.Join(t.TempDir(), "signer.json")}

	s1, err := openSoft(opts, nil)
	require.NoError(t, err)
	pub1 := testPub(t, s1)

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := s1.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub1, digest[:], sig), "signature verification failed")
	assert.Equal(t, MethodSoft, s1.Method())
	require.NoError(t, s1.Close())

	// Reloading from disk must yield the same key.
	st, err := loadState(opts.StatePath)
	require.NoError(t, err)
	s2, err := openSoft(opts, st)
	require.NoError(t, err)
	assert.True(t, pub1.Equal(s2.Public()), "public key changed after reload")
}

// TestSoftSignerWrongMachine verifies a changed machine identity fails
// strictly, or is replaced when Recreate is set.
func TestSoftSignerWrongMachine(t *testing.T) {
	opts := SignerOptions{StatePath: filepath.Join(t.TempDir(), "signer.json")}

	s, err := openSoft(opts, nil)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	st, err := loadState(opts.StatePath)
	require.NoError(t, err)
	_, err = rand.Read(st.Salt)
	require.NoError(t, err)

	_, err = openSoft(opts, st)
	require.ErrorIs(t, err, ErrIdentityChanged)

	opts.Recreate = true
	s2, err := openSoft(opts, st)
	require.NoError(t, err)

	// The replacement key must be persisted.
	st2, err := loadState(opts.StatePath)
	require.NoError(t, err)
	assert.Equal(t, pemOf(t, s2), st2.PubKey, "recovered key was not persisted")
}

// A state that lost part of its key is a changed identity. Where the key is registered, a silent new one
// would only be rejected later.
func TestSoftSignerIncompleteState(t *testing.T) {
	for name, damage := range map[string]func(*state){
		"no salt":     func(st *state) { st.Salt = nil },
		"no nonce":    func(st *state) { st.Nonce = nil },
		"no data":     func(st *state) { st.Data = nil },
		"short nonce": func(st *state) { st.Nonce = st.Nonce[:5] },
	} {
		t.Run(name, func(t *testing.T) {
			opts := testOpts(t, noTPM)
			s, err := NewSigner(opts)
			require.NoError(t, err)
			require.Equal(t, MethodSoft, s.Method())

			st, err := loadState(opts.StatePath)
			require.NoError(t, err)
			damage(st)
			require.NoError(t, saveState(opts.StatePath, st))

			_, err = NewSigner(opts)
			require.ErrorIs(t, err, ErrIdentityChanged)
			kept, err := loadState(opts.StatePath)
			require.NoError(t, err)
			assert.Equal(t, st, kept, "a strict open replaced the state")

			opts.Recreate = true
			s2, err := NewSigner(opts)
			require.NoError(t, err)
			assert.NotEqual(t, pemOf(t, s), pemOf(t, s2))
		})
	}
}

func TestSignerUnreadableState(t *testing.T) {
	for name, content := range map[string]string{
		"empty":     "",
		"truncated": `{"method":"so`,
	} {
		t.Run(name, func(t *testing.T) {
			opts := testOpts(t, noTPM)
			require.NoError(t, os.WriteFile(opts.StatePath, []byte(content), 0o600))

			_, err := NewSigner(opts)
			require.ErrorIs(t, err, ErrIdentityChanged, "the caller cannot tell it has to re-enroll")
			kept, err := os.ReadFile(opts.StatePath)
			require.NoError(t, err)
			assert.Equal(t, content, string(kept), "a strict open replaced the state")

			opts.Recreate = true
			s, err := NewSigner(opts)
			require.NoError(t, err)
			assert.Equal(t, MethodSoft, s.Method())
			assert.Equal(t, MethodSoft, IdentityMethod(opts.StatePath))
		})
	}
}

// Recreate is for an identity that is gone. These two may still be there.
func TestSignerKeepsAnIdentityItCannotOpen(t *testing.T) {
	for name, st := range map[string]*state{
		"a TPM that does not open":  {Method: MethodTPM, PubKey: "pem"},
		"a method of a newer build": {Method: "quantum", PubKey: "pem"},
	} {
		t.Run(name, func(t *testing.T) {
			opts := testOpts(t, noTPM)
			opts.Recreate = true
			require.NoError(t, saveState(opts.StatePath, st))

			_, err := NewSigner(opts)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrIdentityChanged)
			kept, err := loadState(opts.StatePath)
			require.NoError(t, err)
			assert.Equal(t, st, kept)
		})
	}
}

// Software keys are random, so two callers that both find no state must not each make their own.
func TestSignerConcurrentCreation(t *testing.T) {
	opts := testOpts(t, noTPM)
	pems := make([]string, 8)
	var wg sync.WaitGroup
	for i := range pems {
		wg.Go(func() {
			s, err := NewSigner(opts)
			if assert.NoError(t, err) {
				pems[i] = pemOf(t, s)
			}
		})
	}
	wg.Wait()

	st, err := loadState(opts.StatePath)
	require.NoError(t, err)
	for _, got := range pems {
		assert.Equal(t, st.PubKey, got, "a caller holds a key that is not the one on disk")
	}
}

func TestSaveStateIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signer.json")
	require.NoError(t, saveState(path, &state{Method: MethodSoft}))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}
