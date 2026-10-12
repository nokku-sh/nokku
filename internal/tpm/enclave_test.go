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
	return SignerOptions{
		Salt:      []byte("test-signer"),
		StatePath: t.TempDir() + "/signer.json",
		OpenTPM:   noTPM,
		Enclave:   enclave,
	}
}

func TestEnclaveSigner(t *testing.T) {
	opts := enclaveOpts(t, &fakeEnclave{})

	s1, err := NewSigner(opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s1.Method() != MethodEnclave {
		t.Fatalf("Method() = %q, want %q", s1.Method(), MethodEnclave)
	}
	if got := IdentityMethod(opts.StatePath); got != MethodEnclave {
		t.Fatalf("IdentityMethod() = %q, want %q", got, MethodEnclave)
	}
	pub := s1.Public().(*ecdsa.PublicKey)

	digest := sha256.Sum256([]byte("hello nokku"))
	sig, err := s1.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature verification failed")
	}

	// The blob in the state file must reopen as the same key.
	s2, err := NewSigner(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !pub.Equal(s2.Public()) {
		t.Fatal("public key changed after reopening")
	}
	if string(s1.PEM()) != string(s2.PEM()) {
		t.Fatal("PEM changed after reopening")
	}
}

// TestEnclavePreferredOrder verifies a usable TPM wins over the enclave.
func TestEnclavePreferredOrder(t *testing.T) {
	opts := enclaveOpts(t, &fakeEnclave{})
	opts.OpenTPM = simOpen(t)

	s, err := NewSigner(opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	defer func() { _ = s.Close() }()
	if s.Method() != MethodTPM {
		t.Fatalf("Method() = %q, want %q", s.Method(), MethodTPM)
	}
}

// TestEnclaveBlobRejected verifies a blob the enclave no longer opens fails
// strictly, or is replaced when Recreate is set.
func TestEnclaveBlobRejected(t *testing.T) {
	opts := enclaveOpts(t, &fakeEnclave{})

	s, err := NewSigner(opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	oldPEM := string(s.PEM())

	st, err := loadState(opts.StatePath)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	st.Data = []byte("a blob from another machine")
	if err = saveState(opts.StatePath, st); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	if _, err = NewSigner(opts); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("NewSigner strict = %v, want ErrIdentityChanged", err)
	}

	opts.Recreate = true
	s2, err := NewSigner(opts)
	if err != nil {
		t.Fatalf("NewSigner recover: %v", err)
	}
	if string(s2.PEM()) == oldPEM {
		t.Fatal("the recreated identity kept the old public key")
	}
	st2, err := loadState(opts.StatePath)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if st2.Method != MethodEnclave || st2.PubKey != string(s2.PEM()) {
		t.Fatal("recreated identity was not persisted")
	}
}

// TestEnclaveStateWithoutBackend verifies an enclave identity is never
// replaced just because this build has no enclave.
func TestEnclaveStateWithoutBackend(t *testing.T) {
	opts := enclaveOpts(t, &fakeEnclave{})
	if _, err := NewSigner(opts); err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	opts.Enclave = nil
	opts.Recreate = true
	if _, err := NewSigner(opts); err == nil {
		t.Fatal("NewSigner without a backend succeeded, want error")
	}
	if got := IdentityMethod(opts.StatePath); got != MethodEnclave {
		t.Fatalf("state method = %q, want it left at %q", got, MethodEnclave)
	}
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
			opts := enclaveOpts(t, enclave)
			s, err := NewSigner(opts)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			if s.Method() != MethodSoft {
				t.Fatalf("Method() = %q, want %q", s.Method(), MethodSoft)
			}

			strict := enclaveOpts(t, enclave)
			strict.RequireTPM = true
			if _, err = NewSigner(strict); err == nil {
				t.Fatal("NewSigner with RequireTPM succeeded, want error")
			}
			if got := IdentityMethod(strict.StatePath); got != "" {
				t.Fatalf("a failed strict open persisted method %q", got)
			}
		})
	}
}
