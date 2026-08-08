package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/caarlos0/env/v11"
	stripe "github.com/stripe/stripe-go/v86"

	"github.com/nokku-sh/nokku/internal/db"
)

var ErrActiveSubscription = errors.New("workspace already has an active subscription")

// Stripe implements Provider on top of Stripe Billing (Managed Payments).
type Stripe struct {
	client    *stripe.Client
	db        *db.Connection
	returnURL string

	FlexPriceID    string `env:"STRIPE_FLEX_PRICE_ID"`
	LicensePriceID string `env:"STRIPE_LICENSE_PRICE_ID"`
	SecretKey      string `env:"STRIPE_SECRET_KEY"`
	WebhookSecret  string `env:"STRIPE_WEBHOOK_SECRET"`
}

// billableMeters lists resources billed on overage. Each event name must
// match a Stripe Billing Meter with "last" aggregation.
var billableMeters = []struct {
	resource Resource
	event    string
}{
	{ResourceMembers, "nokku_members"},
	{ResourceTargets, "nokku_targets"},
}

// NewStripe returns nil (billing disabled) when a required Stripe env var is
// unset. Returns the Provider interface so the nil value is a nil interface.
func NewStripe(conn *db.Connection, returnURL string) (Provider, error) {
	s, err := env.ParseAs[Stripe]()
	if err != nil {
		return nil, err
	}
	if s.SecretKey == "" || s.WebhookSecret == "" || s.FlexPriceID == "" {
		return nil, nil // billing disabled
	}

	s.db = conn
	s.returnURL = returnURL
	s.client = stripe.NewClient(s.SecretKey)
	return &s, nil
}

// Checkout creates a Checkout Session for the workspace Flex subscription.
func (s *Stripe) Checkout(ctx context.Context, workspaceID, email string) (string, error) {
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}

	// One subscription per workspace: block a new checkout while one is active.
	if _, err := s.db.Q.GetActiveSubscription(ctx, &db.GetActiveSubscriptionParams{
		WorkspaceID: workspaceID,
		Statuses:    ActiveStatuses,
		Sources:     []string{"stripe"},
	}); err == nil {
		return "", ErrActiveSubscription
	}

	customerID, err := s.customerFor(ctx, workspaceID, email)
	if err != nil {
		return "", err
	}

	params := &stripe.CheckoutSessionCreateParams{
		Mode: stripe.String(stripe.CheckoutSessionModeSubscription),
		LineItems: []*stripe.CheckoutSessionCreateLineItemParams{{
			Price:    stripe.String(s.FlexPriceID),
			Quantity: stripe.Int64(1),
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

// customerFor returns the workspace's Stripe customer, reusing the one on the
// subscription row or creating one tagged with the workspace id.
func (s *Stripe) customerFor(ctx context.Context, workspaceID, email string) (string, error) {
	if sub, err := s.db.Q.GetSubscription(ctx, workspaceID); err == nil && sub.CustomerID != "" {
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
	if err := s.db.Q.SetSubscriptionCustomer(ctx, &db.SetSubscriptionCustomerParams{
		WorkspaceID: workspaceID,
		CustomerID:  customer.ID,
	}); err != nil {
		slog.Warn("failed to record customer mapping", "error", err, "workspace_id", workspaceID)
	}
	return customer.ID, nil
}

func (s *Stripe) Portal(ctx context.Context, workspaceID string) (string, error) {
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}
	sub, err := s.db.Q.GetSubscription(ctx, workspaceID)
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
	sub, err := s.db.Q.GetActiveSubscription(ctx, &db.GetActiveSubscriptionParams{
		WorkspaceID: workspaceID,
		Statuses:    ActiveStatuses,
		Sources:     []string{"stripe"},
	})
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
	sub, err := s.db.Q.GetSubscription(ctx, workspaceID)
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
	if err := s.db.Q.UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
		WorkspaceID:       workspaceID,
		Source:            "stripe",
		Plan:              PlanFlex,
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
	subs, err := s.db.Q.ListProviderSubscriptions(ctx, []string{"stripe"})
	if err != nil {
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

// SyncUsage reports daily gauge events for metered billing. Identifiers make
// re-reporting the same day idempotent.
func (s *Stripe) SyncUsage(ctx context.Context) error {
	subs, err := s.db.Q.ListActiveSubscriptions(ctx, &db.ListActiveSubscriptionsParams{
		Statuses: ActiveStatuses,
		Sources:  []string{"stripe"},
	})
	if err != nil {
		return err
	}
	if len(subs) == 0 {
		return nil
	}

	day := time.Now().UTC().Format("2006-01-02")
	for _, sub := range subs {
		if sub.CustomerID == "" {
			continue
		}
		stats, err := s.db.Q.GetWorkspaceStats(ctx, sub.WorkspaceID)
		if err != nil {
			slog.Warn("usage stats lookup failed", "error", err, "workspace_id", sub.WorkspaceID)
			continue
		}
		for _, m := range billableMeters {
			count := usageFor(stats, m.resource)
			if count < 0 {
				continue
			}
			_, err := s.client.V1BillingMeterEvents.Create(
				ctx,
				&stripe.BillingMeterEventCreateParams{
					EventName: stripe.String(m.event),
					Identifier: stripe.String(
						fmt.Sprintf("usage_%s_%s_%s", sub.WorkspaceID, m.event, day),
					),
					Payload: map[string]string{
						"stripe_customer_id": sub.CustomerID,
						"value":              strconv.FormatInt(count, 10),
					},
				},
			)
			if err != nil {
				slog.Warn("failed to report meter event", "error", err,
					"workspace_id", sub.WorkspaceID, "meter", m.event)
			}
		}
	}
	return nil
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

func mapStatus(s stripe.SubscriptionStatus) Status {
	switch s {
	case stripe.SubscriptionStatusActive:
		return StatusActive
	case stripe.SubscriptionStatusTrialing:
		return StatusTrialing
	case stripe.SubscriptionStatusPastDue:
		return StatusPastDue
	case stripe.SubscriptionStatusCanceled,
		stripe.SubscriptionStatusIncomplete,
		stripe.SubscriptionStatusIncompleteExpired,
		stripe.SubscriptionStatusPaused,
		stripe.SubscriptionStatusUnpaid:
		return StatusInactive
	}
	return StatusInactive
}

func usageFor(stats *db.GetWorkspaceStatsRow, r Resource) int64 {
	switch r {
	case ResourceMembers:
		return stats.MemberCount
	case ResourceServiceAccounts:
		return stats.ServiceAccountCount
	case ResourceTargets:
		return stats.TargetCount
	case ResourceTeams:
		return stats.TeamCount
	case ResourceCas:
		return stats.CaCount
	}
	return -1
}
