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

// tpmSigner is a TPM-resident ECDSA P-256 [Signer].
//
// The key is a deterministic primary key. Reopening it with the same salt
// yields the same key pair until the TPM's owner seed changes (TPM clear or
// replacement). The private key never leaves the TPM.
type tpmSigner struct {
	dev  transport.TPMCloser
	hnd  tpm2.TPMHandle
	name tpm2.TPM2BName
	pub  *ecdsa.PublicKey
	pem  []byte
	mu   sync.Mutex
}

// newTPMSigner creates the primary key for salt on dev. On success the signer
// owns dev and Close releases it.
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
	return &tpmSigner{dev: dev, hnd: hnd, name: name, pub: pub, pem: pubPEM}, nil
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.pub }

// Sign signs a SHA-256 digest and returns the DER-encoded ECDSA signature.
func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("tpm: unsupported hash %v (key template pins SHA-256)", opts.HashFunc())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return signECDSA(s.dev, s.hnd, s.name, digest)
}

func (s *tpmSigner) Method() string { return MethodTPM }

func (s *tpmSigner) PEM() []byte { return append([]byte(nil), s.pem...) }

// Close flushes the key handle and closes the TPM transport.
func (s *tpmSigner) Close() error {
	_, err := tpm2.FlushContext{FlushHandle: s.hnd}.Execute(s.dev)
	return errors.Join(err, s.dev.Close())
}
