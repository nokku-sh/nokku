package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// Secret Rotation -----------------------------------------------------------

// RotateSecrets re-encrypts every secret through the active encryptor (a
// crypto.RotatingCipher, reads fall back to the old cipher and writes use the
// new one) and then runs finalize. All in a single transaction, so a crash
// or failure anywhere leaves the database untouched and the rotate-secrets
// command can simply be re-run.
func RotateSecrets(
	ctx context.Context,
	conn *Connection,
	finalize func(ctx context.Context, q *Queries) error,
) error {
	return conn.WithTx(ctx, func(q *Queries) error {
		locked, err := q.TrySecretRotationLock(ctx)
		if err != nil {
			return fmt.Errorf("failed to set advisory lock: %w", err)
		}
		if !locked {
			return errors.New("another secret rotation is already in progress")
		}

		// Fetch all encrypted data (decrypts through active encryptor).
		cas, err := q.GetEncryptedCAKeys(ctx)
		if err != nil {
			return fmt.Errorf("failed to get CAs: %w", err)
		}

		slog.Debug(
			"fetched encrypted secrets",
			"cas",
			len(cas),
		)

		// Re-encrypt CA private keys
		for _, ca := range cas {
			if err := q.UpdateCAPrivateKey(ctx, &UpdateCAPrivateKeyParams{
				ID:         ca.ID,
				PrivateKey: ca.PrivateKey,
			}); err != nil {
				return fmt.Errorf("failed to update CA %s: %w", ca.ID, err)
			}
		}

		if finalize != nil {
			if err := finalize(ctx, q); err != nil {
				return err
			}
		}

		slog.Info("re-encryption complete",
			"cas", len(cas))
		return nil
	})
}
