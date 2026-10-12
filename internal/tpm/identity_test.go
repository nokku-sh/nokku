package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

func newTestSigner(
	t *testing.T,
	open func() (transport.TPMCloser, error),
	mutate func(*SignerOptions),
) Signer {
	t.Helper()
	opts := SignerOptions{
		Salt:      []byte("test-signer"),
		StatePath: t.TempDir() + "/signer.json",
		OpenTPM:   open,
	}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := NewSigner(opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSignerTPM(t *testing.T) {
	open := simOpen(t)

	s1 := newTestSigner(t, open, nil)
	pub1 := s1.Public()
	if s1.Method() != MethodTPM {
		t.Fatalf("Method() = %q, want %q", s1.Method(), MethodTPM)
	}
	if pem := s1.PEM(); len(pem) == 0 {
		t.Fatal("PEM() is empty")
	}

	// The primary key is derived deterministically from the TPM seed, so a
	// fresh signer must produce the same public key (nothing persisted but
	// the public half).
	s2 := newTestSigner(t, open, nil)
	if !pub1.(*ecdsa.PublicKey).Equal(s2.Public().(*ecdsa.PublicKey)) {
		t.Fatal("TPM public key is not deterministic across restarts")
	}

	data := []byte("hello nokku")
	digest := sha256.Sum256(data)
	sig, err := s1.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub1.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature verification failed")
	}
}

// TestSignerSaltIsolation verifies distinct salts yield distinct identities
// on the same TPM.
func TestSignerSaltIsolation(t *testing.T) {
	open := simOpen(t)

	a := newTestSigner(t, open, func(o *SignerOptions) { o.Salt = []byte("nokku-daemon") })
	b := newTestSigner(t, open, func(o *SignerOptions) { o.Salt = []byte("nokku-cli") })
	if a.Public().(*ecdsa.PublicKey).Equal(b.Public().(*ecdsa.PublicKey)) {
		t.Fatal("distinct salts must derive distinct identities")
	}
}

// TestSignerIdentityChanged verifies a persisted public key that no longer
// matches the machine fails with ErrIdentityChanged, unless Recreate is set.
func TestSignerIdentityChanged(t *testing.T) {
	open := simOpen(t)
	dir := t.TempDir() + "/signer.json"

	newOpts := func(recreate bool) SignerOptions {
		return SignerOptions{
			Salt:      []byte("test-signer"),
			StatePath: dir,
			Recreate:  recreate,
			OpenTPM:   open,
		}
	}

	s, err := NewSigner(newOpts(false))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if err = s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Simulate a machine identity change: the persisted public half no
	// longer matches the derived key.
	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	st.PubKey = "-----BEGIN PUBLIC KEY-----\nCHANGED\n-----END PUBLIC KEY-----\n"
	if err = saveState(dir, st); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	if _, err = NewSigner(newOpts(false)); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("NewSigner strict = %v, want ErrIdentityChanged", err)
	}

	// With Recreate the signer replaces the key and persists it.
	s2, err := NewSigner(newOpts(true))
	if err != nil {
		t.Fatalf("NewSigner recover: %v", err)
	}
	defer func() { _ = s2.Close() }()

	st2, err := loadState(dir)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if st2.PubKey != string(s2.PEM()) {
		t.Fatal("recovered identity was not persisted")
	}
}

func TestSignerRequiresSaltAndPath(t *testing.T) {
	if _, err := NewSigner(SignerOptions{StatePath: t.TempDir() + "/signer.json"}); err == nil {
		t.Fatal("NewSigner without salt succeeded, want error")
	}
	if _, err := NewSigner(SignerOptions{Salt: []byte("s")}); err == nil {
		t.Fatal("NewSigner without state path succeeded, want error")
	}
}

func TestSoftSignerRoundTrip(t *testing.T) {
	dir := t.TempDir() + "/signer.json"

	s1, err := openSoft(SignerOptions{
		StatePath: dir,
	}, nil)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	pub1 := s1.Public()

	data := []byte("hello nokku")
	digest := sha256.Sum256(data)
	sig, err := s1.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub1.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature verification failed")
	}
	if s1.Method() != MethodSoft {
		t.Fatalf("Method() = %q, want %q", s1.Method(), MethodSoft)
	}
	if err = s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reloading from disk must yield the same key.
	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st == nil {
		t.Fatal("no state written")
	}
	s2, err := openSoft(SignerOptions{
		StatePath: dir,
	}, st)
	if err != nil {
		t.Fatalf("reload signer: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if !pub1.(*ecdsa.PublicKey).Equal(s2.Public().(*ecdsa.PublicKey)) {
		t.Fatal("public key changed after reload")
	}
}

// TestSoftSignerWrongMachine verifies a changed machine identity fails
// strictly, or is replaced when Recreate is set.
func TestSoftSignerWrongMachine(t *testing.T) {
	dir := t.TempDir() + "/signer.json"
	opts := SignerOptions{
		StatePath: dir,
	}

	s, err := openSoft(opts, nil)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	_ = s.Close()

	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if _, err = rand.Read(st.Salt); err != nil {
		t.Fatalf("corrupt salt: %v", err)
	}

	if _, err = openSoft(opts, st); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("openSoft strict = %v, want ErrIdentityChanged", err)
	}

	opts.Recreate = true
	s2, err := openSoft(opts, st)
	if err != nil {
		t.Fatalf("openSoft recover: %v", err)
	}
	defer func() { _ = s2.Close() }()

	// The replacement key must be persisted.
	st2, err := loadState(dir)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if st2.PubKey != string(s2.PEM()) {
		t.Fatal("recovered key was not persisted")
	}
}
