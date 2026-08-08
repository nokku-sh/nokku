package billing

import (
	"context"
	"net/http"
)

type Provider interface {
	Checkout(ctx context.Context, workspaceID, productID string) (string, error)
	Portal(ctx context.Context, workspaceID string) (string, error)
	Cancel(ctx context.Context, workspaceID string, immediate bool, reason string) error
	Sync(ctx context.Context, workspaceID string)
	SyncAll(ctx context.Context) error
	SyncUsage(ctx context.Context) error
	WebhookHandler() http.Handler
}
