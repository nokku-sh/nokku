// Package tpm provides a machine-bound signing identity backed by a TPM 2.0,
// with a machine-wrapped software fallback for machines without one.
//
// [NewSigner] loads or creates the identity: an ECDSA P-256 key the TPM
// creates and wraps to itself when a TPM is usable, kept as a TSS2 key file,
// otherwise a software P-256 key wrapped to the machine fingerprint. The
// private key never leaves the TPM in the first case and never leaves the
// machine in the second. Every state file holds a key of its own.
//
// A caller on a machine with another hardware key store, such as the macOS
// Secure Enclave, plugs it in through [SignerOptions.Enclave]. It is tried
// after the TPM and before the software key.
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
	// MethodTPM identifies a TPM-backed signing key.
	MethodTPM = "tpm"
	// MethodEnclave identifies a key held by a [SignerOptions.Enclave].
	MethodEnclave = "enclave"
	// MethodSoft identifies a software signing key wrapped to the machine.
	MethodSoft = "soft"
)

// ErrIdentityChanged signals that the machine's signing identity changed
// since the key was created, so the caller must register the new public key.
var ErrIdentityChanged = errors.New("tpm: machine identity changed since the key was created")

// Signer is a machine-bound signing identity and a [crypto.Signer]. It signs
// SHA-256 digests only.
type Signer interface {
	crypto.Signer
	io.Closer

	// Method reports the signing method, MethodTPM, MethodEnclave or
	// MethodSoft.
	Method() string
}

// SignerOptions configures [NewSigner].
type SignerOptions struct {
	// StatePath is where the identity state is persisted, with the TSS2 key
	// file of a TPM key, the opaque blob of an enclave key, or the wrapped
	// private key of a software key. Each path is an identity of its own.
	StatePath string
	// RequireTPM refuses the software fallback. An enclave key satisfies it.
	RequireTPM bool
	// Enclave is the hardware key store tried when no TPM is usable. Nil
	// means the machine has none.
	Enclave Enclave
	// Recreate replaces the key and its state when the persisted identity no
	// longer matches the machine or its state no longer parses, instead of
	// failing with [ErrIdentityChanged]. Interactive callers set it so a
	// re-image does not brick them, and must then invalidate anything derived
	// from the old public key, such as certificates. Leave it unset where the
	// identity is bound to a server-side registration. An identity in a TPM
	// that does not open or load for another reason than a cleared TPM, or of
	// a method this build does not know, is never replaced: the first is often
	// transient and the second may be newer.
	Recreate bool
	// OpenTPM opens the TPM transport, defaulting to the platform device.
	// Tests inject a simulator. The signer owns the returned closer.
	OpenTPM func() (transport.TPMCloser, error)
}

// NewSigner loads or creates the machine's signing identity: a TPM key when
// one is usable, then an enclave key, otherwise a machine-wrapped software
// key (an error when RequireTPM is set). The method is persisted, so an
// existing software identity is never silently upgraded to hardware later.
// Concurrent calls for one state path, from any process, run one at a time.
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
		case MethodEnclave:
			return openEnclave(opts, st)
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
	if opts.Enclave != nil {
		e, encErr := createEnclave(opts)
		if encErr == nil {
			return e, nil
		}
		hwErr = errors.Join(hwErr, encErr)
	}
	if opts.RequireTPM {
		return nil, hwErr
	}
	slog.Warn("no usable hardware key store, using a machine-wrapped software key", "error", hwErr)
	fallback, softErr := openSoft(opts, nil)
	if softErr != nil {
		return nil, errors.Join(hwErr, softErr)
	}
	return fallback, nil
}

// IdentityMethod reports the signing method persisted at statePath
// (MethodTPM, MethodEnclave or MethodSoft) without loading or creating any
// key material.
// It returns "" when no identity exists yet.
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

// A key file that does not parse, or that the TPM refuses as another TPM's, is a changed identity.
func loadTPMIdentity(dev transport.TPMCloser, st *state) (*tpmSigner, error) {
	key, err := keyfile.Decode(st.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: the TPM key file does not parse: %w", ErrIdentityChanged, err)
	}
	return newTPMSigner(dev, key)
}

// The new key signs a test digest before it is saved, so a half-working TPM never becomes an identity that
// cannot log in. On error the caller still owns dev.
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

// selfTest signs and verifies one digest with a new key and returns its public half in PEM.
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

// pemEncodePublicKey returns the PKIX PEM encoding of pub.
func pemEncodePublicKey(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("tpm: encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
