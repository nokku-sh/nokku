package tpm

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// The key stays loaded, a load costs most of a second on a real TPM.
type tpmSigner struct {
	dev transport.TPMCloser
	key *keyfile.TPMKey
	pub crypto.PublicKey

	mu  sync.Mutex
	hnd *tpm2.AuthHandle
}

// On success the signer owns dev and Close releases it.
func newTPMSigner(dev transport.TPMCloser, key *keyfile.TPMKey) (*tpmSigner, error) {
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("tpm: public key of the key file: %w", err)
	}
	s := &tpmSigner{dev: dev, key: key, pub: pub}
	if err = s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.pub }

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("tpm: unsupported hash %v, the identity signs SHA-256 only", opts.HashFunc())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sig, err := s.sign(digest)
	if err == nil {
		return sig, nil
	}
	// A TPM reset, like a resume from hibernate, drops the loaded key.
	s.flush()
	if lerr := s.load(); lerr != nil {
		return nil, errors.Join(err, lerr)
	}
	return s.sign(digest)
}

func (s *tpmSigner) sign(digest []byte) ([]byte, error) {
	if s.hnd == nil {
		return nil, errors.New("tpm: the key is not loaded")
	}
	rsp, err := keyfile.TPMSign(s.dev, *s.hnd, digest, tpm2.TPMAlgSHA256, s.key.KeySize(), s.key.KeyAlgo())
	if err != nil {
		return nil, err
	}
	return keyfile.EncodeSignatureASN1(rsp)
}

// TPM_RC_INTEGRITY means the TPM was cleared or replaced since. Other failures
// may pass, so they never count as a changed identity.
func (s *tpmSigner) load() error {
	parent, _, err := keyfile.CreateSRK(keyfile.NewTPMSession(s.dev), tpm2.TPMRHOwner, nil)
	if err != nil {
		return fmt.Errorf("tpm storage root key: %w", err)
	}
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: parent.Handle}.Execute(s.dev) }()

	// No encrypted session, the private half is wrapped and one costs 300ms.
	rsp, err := tpm2.Load{
		ParentHandle: *parent,
		InPrivate:    s.key.Privkey,
		InPublic:     s.key.Pubkey,
	}.Execute(s.dev)
	if errors.Is(err, tpm2.TPMRCIntegrity) {
		return fmt.Errorf("%w: the TPM no longer loads the key (TPM cleared or replaced)", ErrIdentityChanged)
	}
	if err != nil {
		return fmt.Errorf("load tpm key: %w", err)
	}
	s.hnd = &tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil)}
	return nil
}

func (s *tpmSigner) flush() {
	if s.hnd != nil {
		_, _ = tpm2.FlushContext{FlushHandle: s.hnd.Handle}.Execute(s.dev)
		s.hnd = nil
	}
}

func (s *tpmSigner) Method() string { return MethodTPM }

func (s *tpmSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flush()
	return s.dev.Close()
}
