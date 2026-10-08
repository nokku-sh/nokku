// Package kms does envelope encryption. One Tink keyset, stored in the
// keysets row, encrypts everything at rest. The row is wrapped by a key
// encryption key: a KMS key when KMS_URI is set, otherwise a key derived
// from NOKKU_SECRET.
//
// A rotation adds a new primary key, re-encrypts the small secrets in the
// database with it (see db.Reencrypt) and drops the older keys, so the
// keyset never holds more than two. Recordings are never re-encrypted, each
// has its own key and only that key is. With a KMS this happens on a timer
// while the server runs, together with a rewrap that follows a key rotation
// inside the KMS. A new NOKKU_SECRET, or a move to another KMS, is applied
// with `nokku rotate-secrets`.
package kms

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/nokku-sh/nokku/internal/db"
)

const minSecretLen = 32

type TinkEncryptor struct {
	db *db.Connection

	mu        sync.RWMutex
	kek       tink.AEAD
	primitive tink.AEAD

	KMSURI         string        `env:"KMS_URI"`
	VaultToken     string        `env:"VAULT_TOKEN"`
	RewrapInterval time.Duration `env:"KEYSET_REWRAP_INTERVAL" envDefault:"12h"`
	// RotateInterval is how old the primary key may get with a KMS. Zero
	// turns the timed rotation off.
	RotateInterval time.Duration `env:"KEYSET_ROTATE_INTERVAL" envDefault:"2160h"`
}

// New loads the keyset, or creates it on first boot. secret is NOKKU_SECRET
// and only wraps the keyset when KMS_URI is unset.
func New(ctx context.Context, conn *db.Connection, secret string) (*TinkEncryptor, error) {
	t, err := env.ParseAs[TinkEncryptor]()
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS config: %w", err)
	}
	t.db = conn
	if t.KMSURI != "" {
		t.kek, err = t.kmsKEK(t.KMSURI)
	} else {
		t.kek, err = secretKEK(secret)
	}
	if err != nil {
		return nil, err
	}
	if err := t.load(ctx); err != nil {
		return nil, err
	}
	return &t, nil
}

// ValidSecret refuses a NOKKU_SECRET that is short or a known placeholder.
// The keyset is only as safe as the key derived from it.
func ValidSecret(secret string) error {
	if len(secret) < minSecretLen {
		return fmt.Errorf(
			"NOKKU_SECRET must be at least %d characters, generate one with: openssl rand -hex 32",
			minSecretLen,
		)
	}
	if strings.HasPrefix(secret, "CHANGE_ME") || secret == "0123456789abcdefghijklmnopqrstuv" {
		return errors.New("NOKKU_SECRET is still a placeholder, generate one with: openssl rand -hex 32")
	}
	return nil
}

func secretKEK(secret string) (tink.AEAD, error) {
	if err := ValidSecret(secret); err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, "nokku keyset kek v1", 32)
	if err != nil {
		return nil, err
	}
	return subtle.NewAESGCM(key)
}

func (t *TinkEncryptor) UsesKMS() bool {
	return t.KMSURI != ""
}

func (t *TinkEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.primitive.Encrypt(plaintext, nil)
}

func (t *TinkEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.primitive.Decrypt(ciphertext, nil)
}

// Start keeps a KMS-wrapped keyset fresh until ctx is done. With NOKKU_SECRET
// the keys only change through rotate-secrets, so there is nothing to do.
func (t *TinkEncryptor) Start(ctx context.Context) {
	if !t.UsesKMS() {
		return
	}
	go func() {
		ticker := time.NewTicker(max(t.RewrapInterval, time.Hour))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := t.update(ctx, t.currentKEK(), false); err != nil {
					slog.Error("failed to refresh keyset", "error", err)
				}
			}
		}
	}()
}

// Rotate moves the keyset under a new key encryption key and rotates its
// keys, so nothing in the database is in reach of the old one anymore.
// target is secret:<value> or kms:<uri>.
func (t *TinkEncryptor) Rotate(ctx context.Context, target string) error {
	var kek tink.AEAD
	var err error
	switch scheme, value, _ := strings.Cut(target, ":"); {
	case scheme == "secret" && value != "":
		kek, err = secretKEK(value)
	case scheme == "kms" && value != "":
		kek, err = t.kmsKEK(value)
	default:
		return errors.New("invalid target: must be secret:<value> or kms:<uri>")
	}
	if err != nil {
		return err
	}
	return t.update(ctx, kek, true)
}

func (t *TinkEncryptor) currentKEK() tink.AEAD {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.kek
}

// update rewraps the stored keyset under kek. It first rotates when rotate
// is set or the primary key is older than RotateInterval. Wrapping again with
// the same KMS key follows a rotation inside the KMS. The row lock keeps two
// instances from both rotating, and reading the row picks up what another
// one did.
func (t *TinkEncryptor) update(ctx context.Context, kek tink.AEAD, rotate bool) error {
	current := t.currentKEK()
	var primitive tink.AEAD
	locked := false
	err := t.db.SysTx(ctx, func(q *db.Queries) error {
		row, err := q.LockKeyset(ctx)
		if err != nil {
			return fmt.Errorf("failed to load keyset: %w", err)
		}
		handle, err := unwrap(row.Data, current)
		if err != nil {
			return err
		}
		rotatedAt := row.RotatedAt
		if rotate || (t.RotateInterval > 0 && time.Since(rotatedAt) >= t.RotateInterval) {
			if handle, err = rotateKeys(ctx, q, handle); err != nil {
				return err
			}
			rotatedAt = time.Now()
		}
		data, err := wrap(handle, kek)
		if err != nil {
			return err
		}
		if primitive, err = aead.New(handle); err != nil {
			return fmt.Errorf("failed to create AEAD primitive: %w", err)
		}
		if err := q.UpdateKeyset(ctx, &db.UpdateKeysetParams{Data: data, RotatedAt: rotatedAt}); err != nil {
			return err
		}
		// Held across the commit, so nobody reads a re-encrypted row with
		// the keys from before.
		t.mu.Lock()
		locked = true
		return nil
	})
	if locked {
		defer t.mu.Unlock()
	}
	if err != nil {
		return err
	}
	t.kek = kek
	t.primitive = primitive
	return nil
}

// rotateKeys adds a new primary key, moves every ciphertext in the database
// to it, and drops the older keys. Two keys stay: the new one, and the one it
// replaced, which this process may still write with until the commit.
// Recordings are not touched, only their keys are re-encrypted.
func rotateKeys(ctx context.Context, q *db.Queries, handle *keyset.Handle) (*keyset.Handle, error) {
	outgoing, err := handle.Primary()
	if err != nil {
		return nil, err
	}
	manager := keyset.NewManagerFromHandle(handle)
	id, err := manager.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to add key: %w", err)
	}
	if err := manager.SetPrimary(id); err != nil {
		return nil, fmt.Errorf("failed to set primary key: %w", err)
	}
	all, err := manager.Handle()
	if err != nil {
		return nil, err
	}
	primitive, err := aead.New(all)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD primitive: %w", err)
	}

	// Every ciphertext starts with the id of its key.
	probe, err := primitive.Encrypt([]byte{0}, nil)
	if err != nil {
		return nil, err
	}
	if err := q.Reencrypt(ctx, probe[:cryptofmt.NonRawPrefixSize], func(old []byte) ([]byte, error) {
		plaintext, err := primitive.Decrypt(old, nil)
		if err != nil {
			return nil, err
		}
		return primitive.Encrypt(plaintext, nil)
	}); err != nil {
		return nil, err
	}

	for i := range all.Len() {
		entry, err := all.Entry(i)
		if err != nil {
			return nil, err
		}
		if entry.KeyID() == id || entry.KeyID() == outgoing.KeyID() {
			continue
		}
		if err := manager.Delete(entry.KeyID()); err != nil {
			return nil, fmt.Errorf("failed to drop old key: %w", err)
		}
	}
	return manager.Handle()
}

// load reads the keyset or creates it on first boot. ON CONFLICT DO NOTHING
// makes concurrent first boots safe.
func (t *TinkEncryptor) load(ctx context.Context) error {
	data, err := t.db.Sys().GetKeysetData(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		fresh, newErr := keyset.NewHandle(aead.AES256GCMKeyTemplate())
		if newErr != nil {
			return fmt.Errorf("failed to create keyset: %w", newErr)
		}
		wrapped, wrapErr := wrap(fresh, t.kek)
		if wrapErr != nil {
			return wrapErr
		}
		if _, insertErr := t.db.Sys().InsertKeyset(ctx, wrapped); insertErr != nil {
			return fmt.Errorf("failed to persist initial keyset: %w", insertErr)
		}
		// Read it back, another instance may have won the insert.
		data, err = t.db.Sys().GetKeysetData(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed to load keyset: %w", err)
	}
	handle, err := unwrap(data, t.kek)
	if err != nil {
		return err
	}
	if t.primitive, err = aead.New(handle); err != nil {
		return fmt.Errorf("failed to create AEAD primitive: %w", err)
	}
	return nil
}
