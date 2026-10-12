package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
)

// Enclave is a hardware key store for machines without a TPM, such as the
// macOS Secure Enclave. Its keys are not derived from a seed, so the opaque
// blob it returns is persisted in the state file. The blob only opens on the
// machine that created it.
type Enclave interface {
	// Create makes a new ECDSA P-256 key and returns its blob.
	Create() ([]byte, error)
	// Open loads the key behind blob. The signer signs SHA-256 digests and
	// returns DER-encoded signatures.
	Open(blob []byte) (crypto.Signer, error)
}

// enclaveSigner is an enclave-resident ECDSA P-256 [Signer].
type enclaveSigner struct {
	crypto.Signer

	pem []byte
}

func (s *enclaveSigner) Method() string { return MethodEnclave }

func (s *enclaveSigner) PEM() []byte { return bytes.Clone(s.pem) }

func (s *enclaveSigner) Close() error { return nil }

// openEnclave loads the enclave key from st. A blob the enclave no longer
// opens (another machine, a reset enclave) fails with ErrIdentityChanged, or
// is replaced when SignerOptions.Recreate is set.
func openEnclave(opts SignerOptions, st *state) (Signer, error) {
	if opts.Enclave == nil {
		return nil, errors.New("tpm: the identity lives in a hardware enclave this build cannot use")
	}
	key, err := opts.Enclave.Open(st.Data)
	if err != nil {
		if !opts.Recreate {
			return nil, fmt.Errorf(
				"%w: cannot open the enclave key (%w), re-enroll to create a new key",
				ErrIdentityChanged, err,
			)
		}
		slog.Warn("tpm: enclave key cannot be opened, creating a new key", "error", err)
		return createEnclave(opts)
	}
	// The PEM comes from the key itself, so an edited state file cannot
	// make the signer report another identity.
	pubPEM, err := pemEncodePublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	return &enclaveSigner{Signer: key, pem: pubPEM}, nil
}

// createEnclave makes a new enclave key and persists its blob. The key must
// sign a test digest first, so a half-working enclave falls back to another
// method instead of becoming an identity that cannot log in.
func createEnclave(opts SignerOptions) (Signer, error) {
	blob, err := opts.Enclave.Create()
	if err != nil {
		return nil, fmt.Errorf("tpm: create enclave key: %w", err)
	}
	key, err := opts.Enclave.Open(blob)
	if err != nil {
		return nil, fmt.Errorf("tpm: open new enclave key: %w", err)
	}
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("tpm: enclave key is not ECDSA")
	}

	digest := sha256.Sum256(blob)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("tpm: enclave test signature: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil, errors.New("tpm: enclave test signature does not verify")
	}

	pubPEM, err := pemEncodePublicKey(pub)
	if err != nil {
		return nil, err
	}
	st := &state{Method: MethodEnclave, PubKey: string(pubPEM), Data: blob}
	if err = saveState(opts.StatePath, st); err != nil {
		return nil, err
	}
	return &enclaveSigner{Signer: key, pem: pubPEM}, nil
}
