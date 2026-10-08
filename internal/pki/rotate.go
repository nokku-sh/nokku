package pki

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/ssh"
)

// Rollover gives ca a fresh key and certificate, keeping its id and lifetime.
// The replaced key stays trusted until the certificates it signed have
// expired, unless revokePrevious drops it at once.
func Rollover(
	ctx context.Context,
	q *db.Queries,
	ca *db.CertificateAuthority,
	keyType nokkuv1.CertificateKeyType,
	keyBits int32,
	revokePrevious bool,
) (*db.CertificateAuthority, error) {
	// Older CAs have no stored lifetime.
	lifetime := ca.Lifetime
	if lifetime <= 0 {
		lifetime = ca.NotAfter.Sub(ca.NotBefore)
	}

	var next *ssh.CAInfo
	var err error
	if ca.AuthorityType == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 {
		next, err = NewCA(keyType, keyBits, lifetime)
	} else {
		next, err = ssh.NewCA(keyType, keyBits, lifetime)
	}
	if err != nil {
		return nil, err
	}

	return q.ReplaceCA(ctx, &db.ReplaceCAParams{
		CaID:           ca.ID,
		Certificate:    string(next.Certificate),
		PrivateKey:     next.PrivateKey,
		PublicKey:      next.PublicKey,
		SerialNumber:   next.SerialNumber,
		Subject:        next.Subject,
		NotBefore:      next.NotBefore,
		NotAfter:       next.NotAfter,
		KeyType:        next.KeyType,
		KeyBits:        next.KeyBits,
		RevokePrevious: revokePrevious,
	})
}

// RotateExpiring rolls over every active CA past 80% of its lifetime, once
// at start and then hourly, until ctx is done. Each CA commits on its own and
// SKIP LOCKED lets several instances share the work.
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

// RotateDue is one pass of RotateExpiring, it drains every due CA. A CA that
// fails is skipped for the rest of the pass, so it cannot starve the others,
// and retried on the next one.
func RotateDue(ctx context.Context, conn *db.Connection) {
	failed := []string{}
	for ctx.Err() == nil {
		var picked *db.CertificateAuthority
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
