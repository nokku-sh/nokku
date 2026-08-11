package billing

import (
	"context"
	"errors"
	"net/http"

	"github.com/nokku-sh/nokku/internal/db"
)

var ErrDisabled = errors.New("billing provider is not configured")

// Service is the single billing boundary used by the application. It owns
// policy resolution and optionally delegates commercial operations to Stripe.
type Service struct {
	provider     Provider
	Entitlements *PolicyService
}

func NewService(
	conn *db.Connection,
	license interface{ Valid() bool },
	provider Provider,
	mode Mode,
) *Service {
	return &Service{
		provider:     provider,
		Entitlements: NewPolicyService(conn, license, mode),
	}
}

func (s *Service) Enabled() bool {
	return s != nil && s.provider != nil
}

func (s *Service) Resolve(ctx context.Context, workspaceID string) Plan {
	return s.Entitlements.Resolve(ctx, workspaceID)
}

func (s *Service) Mode() Mode {
	return s.Entitlements.Mode()
}

func (s *Service) Has(ctx context.Context, workspaceID, feature string) bool {
	return s.Entitlements.Has(ctx, workspaceID, feature)
}

func (s *Service) Int(ctx context.Context, workspaceID, key string, fallback int64) int64 {
	return s.Entitlements.Int(ctx, workspaceID, key, fallback)
}

func (s *Service) Check(ctx context.Context, workspaceID string, resource Resource) error {
	return s.Entitlements.Check(ctx, workspaceID, resource)
}

func (s *Service) Checkout(ctx context.Context, workspaceID, email string) (string, error) {
	if !s.Enabled() {
		return "", ErrDisabled
	}
	return s.provider.Checkout(ctx, workspaceID, email)
}

func (s *Service) Portal(ctx context.Context, workspaceID string) (string, error) {
	if !s.Enabled() {
		return "", ErrDisabled
	}
	return s.provider.Portal(ctx, workspaceID)
}

func (s *Service) Cancel(
	ctx context.Context,
	workspaceID string,
	immediate bool,
	reason string,
) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	return s.provider.Cancel(ctx, workspaceID, immediate, reason)
}

func (s *Service) Sync(ctx context.Context, workspaceID string) {
	if s.Enabled() {
		s.provider.Sync(ctx, workspaceID)
	}
}

func (s *Service) SyncAll(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	return s.provider.SyncAll(ctx)
}

func (s *Service) SyncUsage(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	return s.provider.SyncUsage(ctx)
}

func (s *Service) WebhookHandler() http.Handler {
	if !s.Enabled() {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, ErrDisabled.Error(), http.StatusNotFound)
		})
	}
	return s.provider.WebhookHandler()
}
