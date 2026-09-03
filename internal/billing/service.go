package billing

import (
	"context"
	"errors"
	"net/http"

	"github.com/nokku-sh/nokku/internal/db"
)

var ErrDisabled = errors.New("billing provider is not configured")

// Service is the single money-movement boundary used by the application:
// Stripe checkout, portal, cancellation, and subscription reconciliation,
// plus the instance license for self-hosted deployments. Plan resolution
// and enforcement live in internal/entitlement; this package never decides
// what a workspace may do.
type Service struct {
	stripe  *Stripe // nil when the STRIPE_* environment is unset (billing disabled)
	License *Key
}

// New wires the billing layer. It never returns a nil Service: when Stripe
// is unconfigured the service is simply disabled (Enabled() == false), and
// an absent or invalid license yields a zero-value Key so callers rely on
// Valid() == false without nil checks.
func New(conn *db.Connection, baseURL string) (*Service, error) {
	license, err := newLicense()
	if err != nil {
		return nil, err
	}
	stripe, err := newStripe(conn, baseURL)
	if err != nil {
		return nil, err
	}
	return &Service{stripe: stripe, License: license}, nil
}

func (s *Service) Enabled() bool {
	return s.stripe != nil
}

func (s *Service) Checkout(ctx context.Context, workspaceID, email string) (string, error) {
	if !s.Enabled() {
		return "", ErrDisabled
	}
	return s.stripe.Checkout(ctx, workspaceID, email)
}

func (s *Service) Portal(ctx context.Context, workspaceID string) (string, error) {
	if !s.Enabled() {
		return "", ErrDisabled
	}
	return s.stripe.Portal(ctx, workspaceID)
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
	return s.stripe.Cancel(ctx, workspaceID, immediate, reason)
}

func (s *Service) Sync(ctx context.Context, workspaceID string) {
	if s.Enabled() {
		s.stripe.Sync(ctx, workspaceID)
	}
}

func (s *Service) SyncAll(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	return s.stripe.SyncAll(ctx)
}

func (s *Service) WebhookHandler() http.Handler {
	if !s.Enabled() {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, ErrDisabled.Error(), http.StatusNotFound)
		})
	}
	return s.stripe.WebhookHandler()
}
