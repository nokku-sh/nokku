// Package kms implements envelope encryption backed by an external KMS.
//
// A single local Tink keyset of DEKs does all encrypt/decrypt work. The
// keyset is wrapped by a KEK that never leaves the KMS and stored wrapped in
// the database; the KMS sees no plaintext secrets and the database holds only
// ciphertext.
//
// KEK rotation is the KMS's job: it keeps old key versions decryptable, so
// the stored keyset stays readable across rotations. A periodic background
// rewrap migrates it to the current KEK version. There is deliberately no
// automatic DEK rotation: every intermediate state leaves all data
// decryptable. Switching ciphers or rotating the keyset is an explicit
// operator action via the rotate-secrets command, which re-encrypts every
// secret and swaps the keyset atomically in a single transaction.
package kms

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/nokku-sh/nokku/internal/db"
)

type TinkEncryptor struct {
	mu        sync.RWMutex
	client    registry.KMSClient
	kekAEAD   tink.AEAD
	db        *db.Connection
	handle    *keyset.Handle
	primitive tink.AEAD

	KMSURI          string        `env:"KMS_URI"`
	VaultToken      string        `env:"VAULT_TOKEN"`
	VaultSkipVerify bool          `env:"VAULT_SKIP_VERIFY"      envDefault:"false"`
	RewrapInterval  time.Duration `env:"KEYSET_REWRAP_INTERVAL" envDefault:"12h"`
}

func New(ctx context.Context, db *db.Connection) (*TinkEncryptor, error) {
	t, err := newEncryptor(ctx, "")
	if err != nil {
		return nil, err
	}
	t.db = db
	handle, err := t.loadOrCreateKeyset(ctx)
	if err != nil {
		return nil, err
	}
	return t.withHandle(handle)
}

// NewForRotation creates a KMS encryptor with a FRESH keyset that is not persisted anywhere.
func NewForRotation(ctx context.Context, kmsURI string) (*TinkEncryptor, error) {
	t, err := newEncryptor(ctx, kmsURI)
	if err != nil {
		return nil, err
	}
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create keyset: %w", err)
	}
	return t.withHandle(handle)
}

func newEncryptor(ctx context.Context, kmsURI string) (*TinkEncryptor, error) {
	t, err := env.ParseAs[TinkEncryptor]()
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS config: %w", err)
	}
	if kmsURI != "" {
		t.KMSURI = kmsURI
	}
	if t.KMSURI == "" {
		return nil, errors.New("KMS_URI is required")
	}
	if err := t.setupClient(ctx); err != nil {
		return nil, fmt.Errorf("failed to set up KMS client: %w", err)
	}
	return &t, nil
}

func (t *TinkEncryptor) withHandle(handle *keyset.Handle) (*TinkEncryptor, error) {
	primitive, err := aead.New(handle)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD primitive: %w", err)
	}
	t.handle = handle
	t.primitive = primitive
	return t, nil
}

func (t *TinkEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	return t.primitive.Encrypt(plaintext, nil)
}

func (t *TinkEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}
	return t.primitive.Decrypt(ciphertext, nil)
}
