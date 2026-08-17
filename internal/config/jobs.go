package config

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/pki"
	"github.com/nokku-sh/nokku/internal/ssh"
)

func (c *Config) startBackgroundJobs(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.rotateCerts(ctx)
				c.cleanupUnverifiedUsers(ctx)
			}
		}
	}()

	if c.Billing.Enabled() {
		go c.runBillingJobs(ctx)
	}
}

// runBillingJobs reconciles subscription state and reports usage to the
// billing provider.
func (c *Config) runBillingJobs(ctx context.Context) {
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	c.syncBilling(ctx)

	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.syncBilling(ctx)
		}
	}
}

func (c *Config) syncBilling(ctx context.Context) {
	if !c.Billing.Enabled() {
		return
	}
	if err := c.Billing.SyncAll(ctx); err != nil {
		slog.Error("failed to reconcile subscriptions", "error", err)
	}
	if err := c.Billing.SyncUsage(ctx); err != nil {
		slog.Error("failed to report usage", "error", err)
	}
}

func (c *Config) cleanupUnverifiedUsers(ctx context.Context) {
	err := c.Conn.WithTx(ctx, func(q *db.Queries) error {
		return q.DeleteUnverifiedUsers(ctx)
	})
	if err != nil {
		slog.Error("failed to cleanup unverified users", "error", err)
	}
}

func (c *Config) rotateCerts(ctx context.Context) {
	err := c.Conn.WithTx(ctx, func(q *db.Queries) error {
		ca, err := q.GetExpiringCAForUpdate(ctx)
		if err != nil {
			return err
		}

		// Older CAs have no stored lifetime. Fall back to the certificate's
		// own validity span.
		lifetime := ca.Lifetime
		if lifetime <= 0 {
			lifetime = ca.NotAfter.Sub(ca.NotBefore)
		}

		var newCA *ssh.CAInfo
		if ca.AuthorityType == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 {
			newCA, err = pki.NewCA(ca.KeyType, ca.KeyBits, lifetime)
		} else {
			newCA, err = ssh.NewCA(ca.KeyType, ca.KeyBits, lifetime)
		}
		if err != nil {
			return err
		}

		_, err = q.ReplaceCA(ctx, &db.ReplaceCAParams{
			CaID:         ca.ID,
			Certificate:  string(newCA.Certificate),
			PrivateKey:   newCA.PrivateKey,
			PublicKey:    newCA.PublicKey,
			SerialNumber: newCA.SerialNumber,
			Subject:      newCA.Subject,
			NotBefore:    newCA.NotBefore,
			NotAfter:     newCA.NotAfter,
			KeyType:      newCA.KeyType,
			KeyBits:      newCA.KeyBits,
		})

		if err == nil {
			c.Pool.NotifyChange(ca.WorkspaceID)
		}

		return err
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		slog.Error("ca rotation failed", "error", err)
	}
}
