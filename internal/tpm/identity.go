// Package tpm provides a machine-bound signing identity: an ECDSA P-256 key the
// TPM wraps to itself, or a software key wrapped to the machine fingerprint.
// The private key never leaves the TPM in the first case and never leaves the
// machine in the second. Every state file holds a key of its own.
package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	MethodTPM  = "tpm"
	MethodSoft = "soft"
)

// ErrIdentityChanged means the caller must register a new public key.
var ErrIdentityChanged = errors.New("tpm: machine identity changed since the key was created")

// Signer signs SHA-256 digests only.
type Signer interface {
	crypto.Signer
	io.Closer

	Method() string
}

type SignerOptions struct {
	// StatePath holds the key file or wrapped key, one identity per path.
	StatePath string
	// RequireTPM refuses the software fallback.
	RequireTPM bool
	// Recreate replaces a key that no longer matches the machine, or state that
	// no longer parses, instead of failing with [ErrIdentityChanged]. The
	// caller must then invalidate anything derived from the old public key,
	// such as certificates. Leave it unset where the identity is bound to a
	// server-side registration. A TPM that fails for another reason than being
	// cleared, or a method this build does not know, is never replaced: the
	// first is often transient and the second may be newer.
	Recreate bool
	// OpenTPM is a test seam. The signer owns the returned closer.
	OpenTPM func() (transport.TPMCloser, error)
}

// NewSigner persists the method, so a software key is never moved to hardware.
// Calls for one state path run one at a time, across processes.
func NewSigner(opts SignerOptions) (Signer, error) {
	if opts.StatePath == "" {
		return nil, errors.New("tpm: state path is required")
	}

	unlock, err := lockState(opts.StatePath)
	if err != nil {
		return nil, err
	}
	defer unlock()

	st, err := loadState(opts.StatePath)
	switch {
	case errors.Is(err, errNoState):
	case errors.Is(err, errBadState) && opts.Recreate:
		slog.Warn("tpm: signer state is unreadable, creating a new identity", "error", err)
	case errors.Is(err, errBadState):
		return nil, fmt.Errorf("%w: %w, re-enroll to create a new key", ErrIdentityChanged, err)
	case err != nil:
		return nil, err
	}

	if st != nil {
		switch st.Method {
		case MethodTPM:
			return openTPMIdentity(opts, st)
		case MethodSoft:
			if opts.RequireTPM {
				return nil, errors.New(
					"tpm: require-tpm is set but the machine is enrolled with a software key",
				)
			}
			return openSoft(opts, st)
		default:
			return nil, fmt.Errorf(
				"tpm: unknown signer method %q, the identity may come from a newer build",
				st.Method,
			)
		}
	}

	s, tpmErr := openTPMIdentity(opts, nil)
	if tpmErr == nil {
		return s, nil
	}
	hwErr := fmt.Errorf("tpm: no TPM available: %w", tpmErr)
	if opts.RequireTPM {
		return nil, hwErr
	}
	slog.Warn("no usable TPM, using a machine-wrapped software key", "error", hwErr)
	fallback, softErr := openSoft(opts, nil)
	if softErr != nil {
		return nil, errors.Join(hwErr, softErr)
	}
	return fallback, nil
}

// IdentityMethod loads no key material. It is "" when no identity exists.
func IdentityMethod(statePath string) string {
	st, err := loadState(statePath)
	if err != nil || st == nil {
		return ""
	}
	return st.Method
}

func openTPMIdentity(opts SignerOptions, st *state) (Signer, error) {
	open := opts.OpenTPM
	if open == nil {
		open = openTPMDevice
	}
	dev, err := open()
	if err != nil && st != nil {
		return nil, fmt.Errorf("tpm: the identity lives in a TPM that cannot be opened: %w", err)
	}
	if err != nil {
		return nil, err
	}

	if st != nil {
		s, loadErr := loadTPMIdentity(dev, st)
		switch {
		case loadErr == nil:
			return s, nil
		case !errors.Is(loadErr, ErrIdentityChanged):
			_ = dev.Close()
			return nil, loadErr
		case !opts.Recreate:
			_ = dev.Close()
			return nil, fmt.Errorf("%w, re-enroll to register a new key", loadErr)
		}
		slog.Warn("tpm: the TPM no longer loads the key, creating a new one", "error", loadErr)
	}
	s, err := createTPMIdentity(opts, dev)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	return s, nil
}

// An unparsable key file, or one from another TPM, is a changed identity.
func loadTPMIdentity(dev transport.TPMCloser, st *state) (*tpmSigner, error) {
	key, err := keyfile.Decode(st.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: the TPM key file does not parse: %w", ErrIdentityChanged, err)
	}
	return newTPMSigner(dev, key)
}

// A half-working TPM must not become an identity, so the key is tested before
// it is saved. On error the caller still owns dev.
func createTPMIdentity(opts SignerOptions, dev transport.TPMCloser) (*tpmSigner, error) {
	key, err := createTPMKey(dev)
	if err != nil {
		return nil, err
	}
	s, err := newTPMSigner(dev, key)
	if err != nil {
		return nil, err
	}
	pubPEM, err := selfTest(s)
	var file bytes.Buffer
	if err == nil {
		err = keyfile.Encode(&file, key)
	}
	if err == nil {
		err = saveState(opts.StatePath, &state{Method: MethodTPM, PubKey: string(pubPEM), Data: file.Bytes()})
	}
	if err != nil {
		s.flush()
		return nil, err
	}
	return s, nil
}

// selfTest returns the public half in PEM.
func selfTest(key crypto.Signer) ([]byte, error) {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("tpm: the new key is not ECDSA")
	}
	digest := sha256.Sum256([]byte("nokku key self test"))
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("tpm: test signature: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil, errors.New("tpm: the test signature does not verify")
	}
	return pemEncodePublicKey(pub)
}

func pemEncodePublicKey(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("tpm: encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
