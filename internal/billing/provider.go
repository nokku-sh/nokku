// Package billing contains the billing provider port. A provider
// manages hosted checkout/portals, keeps local entitlement state in
// sync, and reports usage for metered billing. Enforcement happens
// in internal/entitlement, never here.
package billing

import (
	"context"
	"net/http"
)

// Provider is the port between nokku and a billing system.
// cfg.Billing is nil when billing is disabled; callers must guard.
type Provider interface {
	Checkout(ctx context.Context, workspaceID string) (string, error)
	Portal(ctx context.Context, workspaceID string) (string, error)
	// Cancel terminates at period end when immediate=false, revokes now
	// when immediate=true.
	Cancel(ctx context.Context, workspaceID string, immediate bool, reason string) error
	// Sync pulls live state for one workspace (self-heals missed webhooks).
	Sync(ctx context.Context, workspaceID string)
	// SyncAll reconciles every provider-managed subscription at startup.
	SyncAll(ctx context.Context) error
	// SyncUsage reports current usage snapshots for metered billing.
	SyncUsage(ctx context.Context) error
	WebhookHandler() http.Handler
}
