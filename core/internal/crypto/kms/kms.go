// Package kms wraps the one Tink keyset with a KMS key or NOKKU_SECRET.
package kms

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const minSecretLen = 32

// ErrServerRunning stops a rotation. A running core can't read what it moves.
var ErrServerRunning = errors.New("a Nokku server is running on this database, stop it first")

// Keyset is fixed at start. Only rotate-secrets changes it, server stopped.
type Keyset struct {
	db *db.Connection

	kek       tink.AEAD
	primitive tink.AEAD
	// vault is nil without a Vault. vaultTokenLoop renews the token on it.
	vault *api.Client

	KMSURI     string `env:"KMS_URI"`
	Secret     string `env:"NOKKU_SECRET"`
	VaultToken string `env:"VAULT_TOKEN"`
}

// New loads the keyset or creates it on first boot.
func New(ctx context.Context, conn *db.Connection, hosted bool) (*Keyset, error) {
	k, err := env.ParseAs[Keyset]()
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS config: %w", err)
	}
	k.db = conn
	switch {
	case k.KMSURI != "":
		if k.Secret != "" {
			slog.Warn("NOKKU_SECRET is not used while KMS_URI is set, remove it")
		}
		k.kek, err = k.kmsKEK(k.KMSURI)
	case hosted:
		// It holds every CA key, a dump plus a secret must not be enough.
		return nil, errors.New("NOKKU_SAAS needs KMS_URI")
	case k.Secret == "":
		return nil, errors.New("set KMS_URI or NOKKU_SECRET, one of them wraps the keyset")
	default:
		k.kek, err = secretKEK(k.Secret)
	}
	if err != nil {
		return nil, err
	}
	if err := k.load(ctx); err != nil {
		return nil, err
	}
	// Rotate swaps k.vault, so the loop keeps the client it started with.
	if k.vault != nil {
		go vaultTokenLoop(ctx, k.vault)
	}
	return &k, nil
}

// Ephemeral is a keyset in memory only, for tests.
func Ephemeral() (*Keyset, error) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, err
	}
	primitive, err := aead.New(handle)
	if err != nil {
		return nil, err
	}
	return &Keyset{primitive: primitive}, nil
}

func secretKEK(secret string) (tink.AEAD, error) {
	if err := validSecret(secret); err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, "nokku keyset kek v1", 32)
	if err != nil {
		return nil, err
	}
	return subtle.NewAESGCM(key)
}

// The keyset is only as safe as the key from NOKKU_SECRET.
func validSecret(secret string) error {
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

// Seal encrypts for the row aad names. db.Reencrypt must build the same aad.
func (k *Keyset) Seal(aad crypto.AAD, plaintext []byte) (crypto.Sealed, error) {
	return k.primitive.Encrypt(plaintext, aad.Bytes())
}

// Open is the one way back to a secret, only for the row aad names.
func (k *Keyset) Open(aad crypto.AAD, sealed crypto.Sealed) ([]byte, error) {
	plaintext, err := k.primitive.Decrypt(sealed, aad.Bytes())
	if err != nil {
		return nil, fmt.Errorf("open %s.%s of row %s: %w", aad.Table, aad.Column, aad.Row, err)
	}
	return plaintext, nil
}

// Rotate makes a new data key, re-encrypts every secret and wraps the keyset
// under target. The same kms URI moves it onto the KMS key's newest version.
func (k *Keyset) Rotate(ctx context.Context, target string) error {
	var kek tink.AEAD
	var err error
	switch scheme, value, _ := strings.Cut(target, ":"); {
	case scheme == "secret" && value != "":
		kek, err = secretKEK(value)
	case scheme == "kms" && value != "":
		kek, err = k.kmsKEK(value)
	default:
		return errors.New("invalid target: must be secret:<value> or kms:<uri>")
	}
	if err != nil {
		return err
	}
	var primitive tink.AEAD
	err = k.db.SysTx(ctx, func(q *db.Queries) error {
		idle, err := q.TryAdvisoryXactLock(ctx, db.ServerLock)
		if err != nil {
			return err
		}
		if !idle {
			return ErrServerRunning
		}
		// The row lock keeps two rotations from running at once.
		row, err := q.LockKeyset(ctx)
		if err != nil {
			return fmt.Errorf("failed to load keyset: %w", err)
		}
		handle, err := unwrap(row.Data, k.kek)
		if err != nil {
			return err
		}
		if handle, err = rotateKeys(ctx, q, handle); err != nil {
			return err
		}
		data, err := wrap(handle, kek)
		if err != nil {
			return err
		}
		if primitive, err = aead.New(handle); err != nil {
			return fmt.Errorf("failed to create AEAD primitive: %w", err)
		}
		return q.UpdateKeyset(ctx, &db.UpdateKeysetParams{Data: data, RotatedAt: time.Now()})
	})
	if err != nil {
		return err
	}
	k.kek = kek
	k.primitive = primitive
	return nil
}

// Keeps the new key and the one it replaced, which this process may write with.
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
	if err := q.Reencrypt(ctx, probe[:cryptofmt.NonRawPrefixSize], func(aad crypto.AAD, old []byte) ([]byte, error) {
		plaintext, err := primitive.Decrypt(old, aad.Bytes())
		if err != nil {
			return nil, fmt.Errorf("open row %s: %w", aad.Row, err)
		}
		return primitive.Encrypt(plaintext, aad.Bytes())
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

func (k *Keyset) load(ctx context.Context) error {
	data, err := k.db.Sys().GetKeysetData(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		fresh, newErr := keyset.NewHandle(aead.AES256GCMKeyTemplate())
		if newErr != nil {
			return fmt.Errorf("failed to create keyset: %w", newErr)
		}
		wrapped, wrapErr := wrap(fresh, k.kek)
		if wrapErr != nil {
			return wrapErr
		}
		if _, insertErr := k.db.Sys().InsertKeyset(ctx, wrapped); insertErr != nil {
			return fmt.Errorf("failed to persist initial keyset: %w", insertErr)
		}
		// Read it back, another instance may have won the insert.
		data, err = k.db.Sys().GetKeysetData(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed to load keyset: %w", err)
	}
	handle, err := unwrap(data, k.kek)
	if err != nil {
		return err
	}
	if k.primitive, err = aead.New(handle); err != nil {
		return fmt.Errorf("failed to create AEAD primitive: %w", err)
	}
	return nil
}
