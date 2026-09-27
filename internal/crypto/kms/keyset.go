package kms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// loadOrCreateKeyset loads the wrapped keyset from the database, creating and
// persisting one on first boot. Concurrent first boots are race-safe: the
// insert uses ON CONFLICT DO NOTHING.
func (t *TinkEncryptor) loadOrCreateKeyset(ctx context.Context) (*keyset.Handle, error) {
	data, err := t.db.Sys().GetKeysetData(ctx)
	switch {
	case err == nil:
		return unwrap(data, t.kek())
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("failed to load keyset: %w", err)
	}

	slog.Debug("no keyset found, creating initial keyset")
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create keyset: %w", err)
	}
	data, err = wrap(handle, t.kek())
	if err != nil {
		return nil, err
	}
	inserted, err := t.db.Sys().InsertKeyset(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to persist initial keyset: %w", err)
	}
	if inserted == 1 {
		return handle, nil
	}

	// Lost a first-boot race: another replica persisted its keyset first.
	slog.Debug("another instance created the keyset first, loading it")
	data, err = t.db.Sys().GetKeysetData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to reload keyset after first-boot race: %w", err)
	}
	return unwrap(data, t.kek())
}

func (t *TinkEncryptor) kek() tink.AEAD {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.kekAEAD
}

// WrappedKeyset returns the keyset wrapped with the current KEK, for atomic
// persistence inside a rotation transaction (see rotate-secrets).
func (t *TinkEncryptor) WrappedKeyset() ([]byte, error) {
	return wrap(t.handle, t.kek())
}

// wrap serializes a keyset and encrypts it with the KEK.
func wrap(handle *keyset.Handle, kek tink.AEAD) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := handle.Write(keyset.NewBinaryWriter(buf), kek); err != nil {
		return nil, fmt.Errorf("failed to wrap keyset: %w", err)
	}
	return buf.Bytes(), nil
}

// unwrap decrypts and parses a wrapped keyset.
func unwrap(data []byte, kek tink.AEAD) (*keyset.Handle, error) {
	handle, err := keyset.Read(keyset.NewBinaryReader(bytes.NewReader(data)), kek)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap keyset (wrong KEK or corrupt data): %w", err)
	}
	return handle, nil
}
