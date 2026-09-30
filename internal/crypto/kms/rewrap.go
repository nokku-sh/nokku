package kms

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

func (t *TinkEncryptor) Start(ctx context.Context) {
	interval := max(t.RewrapInterval, time.Hour)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := t.rewrap(ctx); err != nil {
					slog.Error("failed to rewrap keyset", "error", err)
				}
			}
		}
	}()
}

func (t *TinkEncryptor) rewrap(ctx context.Context) error {
	// Re-fetch so a KMS-side KEK rotation is picked up.
	kek, err := t.client.GetAEAD(t.KMSURI)
	if err != nil {
		return fmt.Errorf("failed to get KMS AEAD: %w", err)
	}
	data, err := wrap(t.handle, kek)
	if err != nil {
		return err
	}
	updated, err := t.db.Sys().UpdateKeysetWrappedData(ctx, data)
	if err != nil {
		return fmt.Errorf("failed to persist rewrapped keyset: %w", err)
	}
	if updated == 0 {
		return errors.New("keyset row missing from database")
	}
	t.mu.Lock()
	t.kekAEAD = kek
	t.mu.Unlock()
	slog.Debug("rewrapped keyset with current KEK")
	return nil
}
