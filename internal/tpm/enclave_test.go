package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEnclave stands in for a hardware enclave: software keys, with the
// PKCS#8 encoding as the blob.
type fakeEnclave struct {
	createErr error
	// badSig makes every opened key sign the wrong digest.
	badSig bool
}

func (f *fakeEnclave) Create() ([]byte, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(key)
}

func (f *fakeEnclave) Open(blob []byte) (crypto.Signer, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(blob)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	if f.badSig {
		return wrongDigestSigner{key}, nil
	}
	return key, nil
}

type wrongDigestSigner struct{ *ecdsa.PrivateKey }

func (s wrongDigestSigner) Sign(r io.Reader, _ []byte, opts crypto.SignerOpts) ([]byte, error) {
	other := sha256.Sum256([]byte("something else"))
	return s.PrivateKey.Sign(r, other[:], opts)
}

func noTPM() (transport.TPMCloser, error) { return nil, errors.New("no tpm in this test") }

func enclaveOpts(t *testing.T, enclave Enclave) SignerOptions {
	t.Helper()
	opts := testOpts(t, noTPM)
	opts.Enclave = enclave
	return opts
}

func TestEnclaveSigner(t *testing.T) {
	opts := enclaveOpts(t, &fakeEnclave{})

	s1, err := NewSigner(opts)
	require.NoError(t, err)
	require.Equal(t, MethodEnclave, s1.Method())
	assert.Equal(t, MethodEnclave, IdentityMethod(opts.StatePath))
	pub := testPub(t, s1)

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := s1.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig), "signature verification failed")

	// The blob in the state file must reopen as the same key.
	s2, err := NewSigner(opts)
	require.NoError(t, err)
	assert.True(t, pub.Equal(s2.Public()), "public key changed after reopening")
}

// TestEnclavePreferredOrder verifies a usable TPM wins over the enclave.
func TestEnclavePreferredOrder(t *testing.T) {
	opts := enclaveOpts(t, &fakeEnclave{})
	opts.OpenTPM = simOpen(openSimulator(t))

	s, err := NewSigner(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	assert.Equal(t, MethodTPM, s.Method())
}

// TestEnclaveBlobRejected verifies a blob the enclave no longer opens fails
// strictly, or is replaced when Recreate is set.
func TestEnclaveBlobRejected(t *testing.T) {
	opts := enclaveOpts(t, &fakeEnclave{})

	s, err := NewSigner(opts)
	require.NoError(t, err)
	oldPEM := pemOf(t, s)

	st, err := loadState(opts.StatePath)
	require.NoError(t, err)
	st.Data = []byte("a blob from another machine")
	require.NoError(t, saveState(opts.StatePath, st))

	_, err = NewSigner(opts)
	require.ErrorIs(t, err, ErrIdentityChanged)

	opts.Recreate = true
	s2, err := NewSigner(opts)
	require.NoError(t, err)
	assert.NotEqual(t, oldPEM, pemOf(t, s2), "the recreated identity kept the old public key")
	st2, err := loadState(opts.StatePath)
	require.NoError(t, err)
	assert.Equal(t, MethodEnclave, st2.Method)
	assert.Equal(t, pemOf(t, s2), st2.PubKey, "recreated identity was not persisted")
}

// TestEnclaveStateWithoutBackend verifies an enclave identity is never
// replaced just because this build has no enclave.
func TestEnclaveStateWithoutBackend(t *testing.T) {
	opts := enclaveOpts(t, &fakeEnclave{})
	_, err := NewSigner(opts)
	require.NoError(t, err)

	opts.Enclave = nil
	opts.Recreate = true
	_, err = NewSigner(opts)
	require.Error(t, err, "NewSigner without a backend succeeded")
	assert.Equal(t, MethodEnclave, IdentityMethod(opts.StatePath), "the state was replaced")
}

// TestEnclaveFallsBackToSoft verifies an enclave that cannot create a working
// key yields a software key, or an error when RequireTPM is set.
func TestEnclaveFallsBackToSoft(t *testing.T) {
	broken := map[string]*fakeEnclave{
		"create fails":       {createErr: errors.New("enclave unavailable")},
		"signature is wrong": {badSig: true},
	}
	for name, enclave := range broken {
		t.Run(name, func(t *testing.T) {
			s, err := NewSigner(enclaveOpts(t, enclave))
			require.NoError(t, err)
			assert.Equal(t, MethodSoft, s.Method())

			strict := enclaveOpts(t, enclave)
			strict.RequireTPM = true
			_, err = NewSigner(strict)
			require.Error(t, err, "NewSigner with RequireTPM succeeded")
			assert.Empty(t, IdentityMethod(strict.StatePath), "a failed strict open persisted a method")
		})
	}
}
