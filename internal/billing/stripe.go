package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
	stripe "github.com/stripe/stripe-go/v86"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

var ErrActiveSubscription = errors.New("workspace already has an active subscription")

// minBillableSeats is the smallest per-seat subscription: the pricing floor
// (5 seats × €96/user/yr = €480/yr, see §4.2 of the monetization plan).
const minBillableSeats = 5

// Stripe implements Provider on top of Stripe Billing (Managed Payments).
type Stripe struct {
	client    *stripe.Client
	db        *db.Connection
	returnURL string

	ProPriceID     string `env:"STRIPE_PRO_PRICE_ID"`
	LicensePriceID string `env:"STRIPE_LICENSE_PRICE_ID"`
	SecretKey      string `env:"STRIPE_SECRET_KEY"`
	WebhookSecret  string `env:"STRIPE_WEBHOOK_SECRET"`
}

// newStripe returns nil (billing disabled) when a required Stripe env var
// is unset.
func newStripe(conn *db.Connection, returnURL string) (*Stripe, error) {
	s, err := env.ParseAs[Stripe]()
	if err != nil {
		return nil, err
	}
	if s.SecretKey == "" || s.WebhookSecret == "" || s.ProPriceID == "" {
		return nil, nil // billing disabled
	}

	s.db = conn
	s.returnURL = returnURL
	s.client = stripe.NewClient(s.SecretKey)
	return &s, nil
}

// Checkout creates a Checkout Session for the workspace's Pro per-seat
// subscription. Quantity is the current member count (never below the
// pricing floor); seat count changes are handled by the customer in the
// Stripe portal. There is deliberately no quantity-sync job — that would
// reintroduce the usage-reporting machinery this design deletes. Known
// gap: seats added between checkout and the next portal edit are unbilled
// until the customer adjusts quantity.
func (s *Stripe) Checkout(ctx context.Context, workspaceID, email string) (string, error) {
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}

	// One subscription per workspace: block a new checkout while one is active.
	if _, err := s.activeSubscription(ctx, workspaceID); err == nil {
		return "", ErrActiveSubscription
	}

	customerID, err := s.customerFor(ctx, workspaceID, email)
	if err != nil {
		return "", err
	}

	quantity, err := s.billableSeats(ctx, workspaceID)
	if err != nil {
		return "", err
	}

	params := &stripe.CheckoutSessionCreateParams{
		Mode: stripe.String(stripe.CheckoutSessionModeSubscription),
		LineItems: []*stripe.CheckoutSessionCreateLineItemParams{{
			Price:    stripe.String(s.ProPriceID),
			Quantity: new(quantity),
		}},
		SuccessURL:        stripe.String(s.returnURL + "/profile/billing"),
		CancelURL:         stripe.String(s.returnURL + "/profile/billing"),
		ClientReferenceID: stripe.String(workspaceID),
		Customer:          stripe.String(customerID),
		CustomerEmail:     stripe.String(email),
		SubscriptionData: &stripe.CheckoutSessionCreateSubscriptionDataParams{
			Metadata: map[string]string{"workspace_id": workspaceID},
		},
	}

	session, err := s.client.V1CheckoutSessions.Create(ctx, params)
	if err != nil {
		return "", fmt.Errorf("create checkout session: %w", err)
	}
	return session.URL, nil
}

// The helpers below read and write subscription state in system
// transactions: workspace_subscriptions is under RLS and the Stripe flows
// (checkout, portal, webhooks, sync jobs) operate outside a tenant scope.

func (s *Stripe) subscription(
	ctx context.Context,
	workspaceID string,
) (*db.WorkspaceSubscription, error) {
	var sub *db.WorkspaceSubscription
	if err := s.db.WithTx(ctx, func(q *db.Queries) (err error) {
		sub, err = q.GetSubscription(ctx, workspaceID)
		return err
	}); err != nil {
		return nil, err
	}
	return sub, nil
}

func (s *Stripe) activeSubscription(
	ctx context.Context,
	workspaceID string,
) (*db.WorkspaceSubscription, error) {
	var sub *db.WorkspaceSubscription
	if err := s.db.WithTx(ctx, func(q *db.Queries) (err error) {
		sub, err = q.GetActiveSubscription(ctx, &db.GetActiveSubscriptionParams{
			WorkspaceID: workspaceID,
			Statuses:    entitlement.ActiveStatuses,
			Sources:     []string{"stripe"},
		})
		return err
	}); err != nil {
		return nil, err
	}
	return sub, nil
}

func (s *Stripe) upsertSubscription(
	ctx context.Context,
	params *db.UpsertSubscriptionParams,
) error {
	return s.db.WithTx(ctx, func(q *db.Queries) error {
		return q.UpsertSubscription(ctx, params)
	})
}

// customerFor returns the workspace's Stripe customer, reusing the one on the
// subscription row or creating one tagged with the workspace id.
func (s *Stripe) customerFor(ctx context.Context, workspaceID, email string) (string, error) {
	if sub, err := s.subscription(ctx, workspaceID); err == nil && sub.CustomerID != "" {
		return sub.CustomerID, nil
	}

	params := &stripe.CustomerCreateParams{
		Metadata: map[string]string{"workspace_id": workspaceID},
	}
	if email != "" {
		params.Email = stripe.String(email)
	}
	customer, err := s.client.V1Customers.Create(ctx, params)
	if err != nil {
		return "", fmt.Errorf("create customer: %w", err)
	}

	// Record the mapping so later checkouts reuse the same customer.
	if err := s.db.WithTx(ctx, func(q *db.Queries) error {
		return q.SetSubscriptionCustomer(ctx, &db.SetSubscriptionCustomerParams{
			WorkspaceID: workspaceID,
			CustomerID:  customer.ID,
		})
	}); err != nil {
		slog.Warn("failed to record customer mapping", "error", err, "workspace_id", workspaceID)
	}
	return customer.ID, nil
}

func (s *Stripe) Portal(ctx context.Context, workspaceID string) (string, error) {
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}
	sub, err := s.subscription(ctx, workspaceID)
	if err != nil || sub.CustomerID == "" {
		return "", errors.New("no Stripe customer for this workspace")
	}

	session, err := s.client.V1BillingPortalSessions.Create(
		ctx,
		&stripe.BillingPortalSessionCreateParams{
			Customer:  stripe.String(sub.CustomerID),
			ReturnURL: stripe.String(s.returnURL + "/profile/billing"),
		},
	)
	if err != nil {
		return "", fmt.Errorf("create portal session: %w", err)
	}
	return session.URL, nil
}

// Cancel terminates the Stripe subscription: immediately, or at period end.
func (s *Stripe) Cancel(
	ctx context.Context,
	workspaceID string,
	immediate bool,
	reason string,
) error {
	if workspaceID == "" {
		return errors.New("missing workspace ID")
	}
	sub, err := s.activeSubscription(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("get active subscription: %w", err)
	}
	if sub.SubscriptionID == "" {
		return nil // no Stripe subscription to cancel
	}

	if immediate {
		_, err = s.client.V1Subscriptions.Cancel(ctx, sub.SubscriptionID, nil)
		return err
	}

	params := &stripe.SubscriptionUpdateParams{CancelAtPeriodEnd: new(true)}
	if reason != "" {
		params.CancellationDetails = &stripe.SubscriptionUpdateCancellationDetailsParams{
			Comment: stripe.String(reason),
		}
	}
	if _, err = s.client.V1Subscriptions.Update(ctx, sub.SubscriptionID, params); err != nil {
		return err
	}
	s.Sync(ctx, workspaceID)
	return nil
}

// Sync reconciles one workspace from Stripe (self-heals missed webhooks).
func (s *Stripe) Sync(ctx context.Context, workspaceID string) {
	sub, err := s.subscription(ctx, workspaceID)
	if err != nil || sub.SubscriptionID == "" || sub.Source != "stripe" {
		return
	}
	remote, err := s.client.V1Subscriptions.Retrieve(
		ctx, sub.SubscriptionID,
		&stripe.SubscriptionRetrieveParams{},
	)
	if err != nil {
		slog.Warn("failed to fetch Stripe subscription", "error", err, "workspace_id", workspaceID)
		return
	}
	if err := s.upsertSubscription(ctx, &db.UpsertSubscriptionParams{
		WorkspaceID:       workspaceID,
		Source:            "stripe",
		Plan:              entitlement.PlanPro,
		Status:            string(mapStatus(remote.Status)),
		CustomerID:        remote.Customer.ID,
		SubscriptionID:    remote.ID,
		CurrentPeriodEnd:  periodEnd(remote),
		CancelAtPeriodEnd: sub.CancelAtPeriodEnd,
	}); err != nil {
		slog.Warn("failed to upsert subscription", "error", err, "workspace_id", workspaceID)
	}
}

// SyncAll reconciles every Stripe-managed row. Runs at startup.
func (s *Stripe) SyncAll(ctx context.Context) error {
	var subs []*db.WorkspaceSubscription
	if err := s.db.WithTx(ctx, func(q *db.Queries) (err error) {
		subs, err = q.ListProviderSubscriptions(ctx, []string{"stripe"})
		return err
	}); err != nil {
		return err
	}
	for _, sub := range subs {
		s.Sync(ctx, sub.WorkspaceID)
	}
	if len(subs) > 0 {
		slog.Info("reconciled subscriptions", "count", len(subs))
	}
	return nil
}

// billableSeats returns the quantity for the per-seat subscription: the
// current member count, never below the pricing floor.
func (s *Stripe) billableSeats(ctx context.Context, workspaceID string) (int64, error) {
	var count int64
	if err := s.db.WithTx(ctx, func(q *db.Queries) (err error) {
		count, err = q.CountWorkspaceSeats(ctx, workspaceID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("count members for checkout: %w", err)
	}
	return max(count, minBillableSeats), nil
}

// periodEnd returns the current period end for a single-item subscription.
func periodEnd(sub *stripe.Subscription) *time.Time {
	if sub.Items == nil || len(sub.Items.Data) == 0 {
		return nil
	}
	end := sub.Items.Data[0].CurrentPeriodEnd
	if end == 0 {
		return nil
	}
	t := time.Unix(end, 0).UTC()
	return &t
}

func mapStatus(s stripe.SubscriptionStatus) entitlement.Status {
	switch s {
	case stripe.SubscriptionStatusActive:
		return entitlement.StatusActive
	case stripe.SubscriptionStatusTrialing:
		return entitlement.StatusTrialing
	case stripe.SubscriptionStatusPastDue:
		return entitlement.StatusPastDue
	case stripe.SubscriptionStatusCanceled,
		stripe.SubscriptionStatusIncomplete,
		stripe.SubscriptionStatusIncompleteExpired,
		stripe.SubscriptionStatusPaused,
		stripe.SubscriptionStatusUnpaid:
		return entitlement.StatusInactive
	}
	return entitlement.StatusInactive
}
