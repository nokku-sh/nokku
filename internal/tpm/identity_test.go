package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrongKey signs with another key than it shows, like a half-broken key store.
type wrongKey struct {
	crypto.Signer

	shows crypto.PublicKey
}

func testOpts(t *testing.T, open func() (transport.TPMCloser, error)) SignerOptions {
	t.Helper()
	return SignerOptions{
		StatePath: filepath.Join(t.TempDir(), "signer.json"),
		OpenTPM:   open,
	}
}

func newTestSigner(t *testing.T, open func() (transport.TPMCloser, error)) Signer {
	t.Helper()
	s, err := NewSigner(testOpts(t, open))
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

func noTPM() (transport.TPMCloser, error) { return nil, errors.New("no tpm in this test") }

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

// Two state files on one TPM are two identities, like DPoP and host keys.
func TestSignerStateFilesAreSeparate(t *testing.T) {
	open := simOpen(openSimulator(t))

	a := newTestSigner(t, open)
	b := newTestSigner(t, open)
	assert.False(t, testPub(t, a).Equal(b.Public()), "two state files must hold two keys")
}

// A key the TPM no longer loads is a changed identity, unless Recreate is set.
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

	opts.Recreate = true
	s2, err := NewSigner(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })
	assert.NotEqual(t, before, pemOf(t, s2))

	st2, err := loadState(opts.StatePath)
	require.NoError(t, err)
	assert.Equal(t, pemOf(t, s2), st2.PubKey, "recovered identity was not persisted")
}

// Older builds derived keys and left no key file. That is a changed identity.
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

// No TPM gets a software key, like a Mac. RequireTPM refuses one at any time.
func TestSignerWithoutATPM(t *testing.T) {
	opts := testOpts(t, noTPM)
	opts.RequireTPM = true
	_, err := NewSigner(opts)
	require.ErrorContains(t, err, "no TPM available")
	assert.Empty(t, IdentityMethod(opts.StatePath), "a refusal leaves no identity")

	opts.RequireTPM = false
	s, err := NewSigner(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	assert.Equal(t, MethodSoft, s.Method())
	assert.Equal(t, MethodSoft, IdentityMethod(opts.StatePath))

	opts.RequireTPM = true
	_, err = NewSigner(opts)
	assert.ErrorContains(t, err, "require-tpm is set")
}

func (k wrongKey) Public() crypto.PublicKey { return k.shows }

// A key that can't sign must never become an identity nobody can log in with.
func TestSelfTestRefusesAKeyThatDoesNotSign(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = selfTest(key)
	require.NoError(t, err)
	_, err = selfTest(wrongKey{Signer: key, shows: other.Public()})
	assert.Error(t, err)
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
	_, err = s1.Sign(rand.Reader, digest[:], crypto.SHA512)
	require.Error(t, err, "a TPM refuses other hashes, software must act the same")
	require.NoError(t, s1.Close())

	st, err := loadState(opts.StatePath)
	require.NoError(t, err)
	s2, err := openSoft(opts, st)
	require.NoError(t, err)
	assert.True(t, pub1.Equal(s2.Public()), "public key changed after reload")
}

// A changed machine identity fails, or is replaced when Recreate is set.
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

	st2, err := loadState(opts.StatePath)
	require.NoError(t, err)
	assert.Equal(t, pemOf(t, s2), st2.PubKey, "recovered key was not persisted")
}

// A damaged state is a changed identity, a silent new key gets rejected later.
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

// Software keys are random, so two callers with no state must share one.
func TestSignerConcurrentCreation(t *testing.T) {
	opts := testOpts(t, noTPM)
	signers := make([]Signer, 8)
	errs := make([]error, len(signers))
	var wg sync.WaitGroup
	for i := range signers {
		wg.Go(func() { signers[i], errs[i] = NewSigner(opts) })
	}
	wg.Wait()
	require.NoError(t, errors.Join(errs...))

	st, err := loadState(opts.StatePath)
	require.NoError(t, err)
	for _, s := range signers {
		assert.Equal(t, st.PubKey, pemOf(t, s), "a caller holds a key that is not the one on disk")
	}
}

func TestSaveStateIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signer.json")
	require.NoError(t, saveState(path, &state{Method: MethodSoft}))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}
