package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// Secret Rotation -----------------------------------------------------------

// RotateSecrets re-encrypts every secret through the active encryptor (a
// crypto.RotatingCipher: reads fall back to the old cipher, writes use the
// new one) and then runs finalize — all in a single transaction, so a crash
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
		oidc, err := q.GetEncryptedOIDCSecrets(ctx)
		if err != nil {
			return fmt.Errorf("failed to get OIDC providers: %w", err)
		}
		saml, err := q.GetEncryptedSAMLKeys(ctx)
		if err != nil {
			return fmt.Errorf("failed to get SAML providers: %w", err)
		}
		slog.Debug(
			"Fetched encrypted secrets",
			"cas",
			len(cas),
			"oidc",
			len(oidc),
			"saml",
			len(saml),
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

		// Re-encrypt OIDC client secrets
		for _, provider := range oidc {
			if err := q.UpdateOIDCClientSecret(ctx, &UpdateOIDCClientSecretParams{
				WorkspaceID:  provider.WorkspaceID,
				ClientSecret: provider.ClientSecret,
			}); err != nil {
				return fmt.Errorf(
					"failed to update OIDC provider %s: %w",
					provider.WorkspaceID,
					err,
				)
			}
		}

		// Re-encrypt SAML private keys
		for _, provider := range saml {
			if err := q.UpdateSAMLPrivateKey(ctx, &UpdateSAMLPrivateKeyParams{
				WorkspaceID:  provider.WorkspaceID,
				SpPrivateKey: provider.SpPrivateKey,
			}); err != nil {
				return fmt.Errorf(
					"failed to update SAML provider %s: %w",
					provider.WorkspaceID,
					err,
				)
			}
		}

		if err := finalize(ctx, q); err != nil {
			return err
		}

		slog.Info("Re-encryption complete",
			"cas", len(cas), "oidc", len(oidc),
			"saml", len(saml))
		return nil
	})
}
