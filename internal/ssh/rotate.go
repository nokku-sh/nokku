package ssh

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
)

// Rollover keeps the replaced key trusted until its certificates expire, unless revokePrevious drops it.
func Rollover(
	ctx context.Context,
	q *db.Queries,
	ca *db.SSHCA,
	keyType nokkuv1.CertificateKeyType,
	keyBits int32,
	revokePrevious bool,
) (*db.SSHCA, error) {
	// Older CAs have no stored lifetime.
	lifetime := ca.Lifetime
	if lifetime <= 0 {
		lifetime = ca.NotAfter.Sub(ca.NotBefore)
	}

	next, err := NewCA(keyType, keyBits, lifetime)
	if err != nil {
		return nil, err
	}

	return q.ReplaceCA(ctx, &db.ReplaceCAParams{
		CaID:           ca.ID,
		PrivateKey:     next.PrivateKey,
		PublicKey:      next.PublicKey,
		NotBefore:      next.NotBefore,
		NotAfter:       next.NotAfter,
		KeyType:        next.KeyType,
		KeyBits:        next.KeyBits,
		RevokePrevious: revokePrevious,
	})
}

// RotateExpiring rolls over every active CA past 80% of its lifetime. SKIP LOCKED lets instances share the work.
func RotateExpiring(ctx context.Context, conn *db.Connection) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		RotateDue(ctx, conn)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RotateDue is one pass of RotateExpiring. A CA that fails is skipped for the pass, so it cannot starve the others.
func RotateDue(ctx context.Context, conn *db.Connection) {
	failed := []string{}
	for ctx.Err() == nil {
		var picked *db.SSHCA
		err := conn.SysTx(ctx, func(q *db.Queries) error {
			var err error
			if picked, err = q.GetExpiringCAForUpdate(ctx, failed); err != nil {
				return err
			}
			_, err = Rollover(ctx, q, picked, picked.KeyType, picked.KeyBits, false)
			return err
		})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return
		case err != nil && picked == nil:
			slog.Error("ca rotation: finding due certificate authorities", "error", err)
			return
		case err != nil:
			slog.Error("ca rotation failed", "ca_id", picked.ID, "workspace_id", picked.WorkspaceID, "error", err)
			failed = append(failed, picked.ID)
		}
	}
}
