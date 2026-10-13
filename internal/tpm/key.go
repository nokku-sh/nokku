package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// tpmSigner signs with a deterministic primary key that never leaves the TPM.
type tpmSigner struct {
	dev  transport.TPMCloser
	salt []byte
	hnd  tpm2.TPMHandle
	name tpm2.TPM2BName
	pub  *ecdsa.PublicKey
	pem  []byte
	mu   sync.Mutex
}

// On success the signer owns dev and Close releases it.
func newTPMSigner(dev transport.TPMCloser, salt []byte) (*tpmSigner, error) {
	hnd, name, pub, err := createPrimary(dev, salt)
	if err != nil {
		return nil, err
	}
	pubPEM, err := pemEncodePublicKey(pub)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: hnd}.Execute(dev)
		return nil, err
	}
	return &tpmSigner{dev: dev, salt: salt, hnd: hnd, name: name, pub: pub, pem: pubPEM}, nil
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.pub }

// Sign signs a SHA-256 digest and returns the DER-encoded ECDSA signature.
func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("tpm: unsupported hash %v (key template pins SHA-256)", opts.HashFunc())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sig, err := signECDSA(s.dev, s.hnd, s.name, digest)
	if err == nil {
		return sig, nil
	}
	// A TPM reset, such as a resume from hibernate, drops the handle. The key is derived, so it comes back.
	if rerr := s.reload(); rerr != nil {
		return nil, errors.Join(err, rerr)
	}
	return signECDSA(s.dev, s.hnd, s.name, digest)
}

// reload derives the key again and refuses one that is not the key the signer started with.
func (s *tpmSigner) reload() error {
	_, _ = tpm2.FlushContext{FlushHandle: s.hnd}.Execute(s.dev)
	hnd, name, pub, err := createPrimary(s.dev, s.salt)
	if err != nil {
		return err
	}
	if !pub.Equal(s.pub) {
		_, _ = tpm2.FlushContext{FlushHandle: hnd}.Execute(s.dev)
		return fmt.Errorf("%w: the TPM key changed while in use", ErrIdentityChanged)
	}
	s.hnd, s.name = hnd, name
	return nil
}

func (s *tpmSigner) Method() string { return MethodTPM }

// Close flushes the key handle and closes the TPM transport.
func (s *tpmSigner) Close() error {
	_, err := tpm2.FlushContext{FlushHandle: s.hnd}.Execute(s.dev)
	return errors.Join(err, s.dev.Close())
}
