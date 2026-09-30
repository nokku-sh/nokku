package billing

import (
	"context"
	"errors"
	"net/http"

	"github.com/mizuchilabs/kata/licx"

	"github.com/nokku-sh/nokku/internal/db"
)

var ErrDisabled = errors.New("billing provider is not configured")

// Service moves money. It never decides what a workspace may do, that is
// internal/entitlement.
type Service struct {
	stripe  *Stripe // nil when the STRIPE_* environment is unset (billing disabled)
	License *licx.Claims
}

// New never returns a nil Service, an unconfigured one is just disabled.
// License is nil when absent or invalid.
func New(ctx context.Context, conn *db.Connection, baseURL string) (*Service, error) {
	stripe, err := newStripe(conn, baseURL)
	if err != nil {
		return nil, err
	}
	if stripe != nil {
		go stripe.reconcile(ctx)
	}
	return &Service{stripe: stripe, License: verifyLicense()}, nil
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

func (s *Service) WebhookHandler() http.Handler {
	if !s.Enabled() {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, ErrDisabled.Error(), http.StatusNotFound)
		})
	}
	return s.stripe.WebhookHandler()
}
