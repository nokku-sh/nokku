package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	stripe "github.com/stripe/stripe-go/v86"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	"github.com/nokku-sh/nokku/internal/meta"
)

// stripeSources are the local rows managed by the Stripe provider.
var stripeSources = []string{"stripe"}

// ErrActiveSubscription is returned when a workspace already has an active
// subscription. Stripe does not enforce one subscription per tenant, so the
// Checkout gate and a webhook backstop together enforce it.
var ErrActiveSubscription = errors.New("workspace already has an active subscription")

// Stripe implements Provider on top of Stripe Billing (Managed Payments).
type Stripe struct {
	client    *stripe.Client
	db        *db.Connection
	returnURL string

	// FlexPriceIDs are the price IDs that make up the Flex plan.
	FlexPriceIDs string `env:"STRIPE_FLEX_PRICE_IDS"`
	// LicensePriceID is the yearly price for the Enterprise license key.
	LicensePriceID string `env:"STRIPE_LICENSE_PRICE_ID"`
	// SecretKey is the Stripe secret key. Never ship it in self-hosted builds.
	SecretKey string `env:"STRIPE_SECRET_KEY"`
	// WebhookSecret is the signing secret for /webhooks/stripe.
	WebhookSecret string `env:"STRIPE_WEBHOOK_SECRET"`
}

// billableMeters lists resources billed on overage. Each event name must
// match a Stripe Billing Meter with "last" aggregation.
var billableMeters = []struct {
	resource entitlement.Resource
	event    string
}{
	{entitlement.ResourceMembers, "nokku_members"},
	{entitlement.ResourceServiceAccounts, "nokku_service_accounts"},
	{entitlement.ResourceTargets, "nokku_targets"},
}

// NewStripe returns nil (billing disabled) when a required Stripe env var is
// unset. Returns the Provider interface so the nil value is a nil interface.
func NewStripe(conn *db.Connection, returnURL string) (Provider, error) {
	s, err := env.ParseAs[Stripe]()
	if err != nil {
		return nil, err
	}
	if s.SecretKey == "" || s.WebhookSecret == "" || s.FlexPriceIDs == "" {
		return nil, nil // billing disabled
	}

	s.db = conn
	s.returnURL = returnURL
	s.client = stripe.NewClient(s.SecretKey)
	return &s, nil
}

// Checkout creates a Checkout Session for the workspace Flex subscription,
// carrying the workspace id in subscription metadata so webhooks can map it
// back. Each workspace may hold at most one active subscription, so a checkout
// is refused while one exists.
func (s *Stripe) Checkout(ctx context.Context, workspaceID, productID string) (string, error) {
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}
	// Only Flex is a workspace-scoped subscription. The Enterprise license is
	// bought via the license worker's Payment Link, never through this endpoint.
	if productID != "" && productID != entitlement.PlanFlex {
		return "", errors.New("unsupported product")
	}

	// One subscription per workspace: block a new checkout while one is active.
	if _, err := s.db.Q.GetActiveSubscription(ctx, &db.GetActiveSubscriptionParams{
		WorkspaceID: workspaceID,
		Statuses:    entitlement.ActiveStatuses,
		Sources:     stripeSources,
	}); err == nil {
		return "", ErrActiveSubscription
	}

	lineItems := make([]*stripe.CheckoutSessionCreateLineItemParams, 0, 1)
	for _, id := range s.flexPrices() {
		lineItems = append(lineItems, &stripe.CheckoutSessionCreateLineItemParams{
			Price:    stripe.String(id),
			Quantity: stripe.Int64(1),
		})
	}
	if len(lineItems) == 0 {
		return "", errors.New("unsupported product")
	}

	email := ""
	if userID := meta.UserIDFromContext(ctx); userID != "" {
		if user, err := s.db.Q.GetUserByID(ctx, userID); err == nil {
			email = user.Email
		}
	}
	customerID, err := s.customerFor(ctx, workspaceID, email)
	if err != nil {
		return "", err
	}

	params := &stripe.CheckoutSessionCreateParams{
		Mode:              stripe.String(stripe.CheckoutSessionModeSubscription),
		LineItems:         lineItems,
		SuccessURL:        stripe.String(s.returnURL + "/profile/billing"),
		CancelURL:         stripe.String(s.returnURL + "/profile/billing"),
		ClientReferenceID: stripe.String(workspaceID),
		Customer:          stripe.String(customerID),
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

// customerFor returns the workspace's Stripe customer, reusing the one recorded
// on the subscription row or creating a new one tagged with the workspace id so
// customers can be reconciled by workspace.
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

	// Record the mapping so later checkouts reuse the same customer even if
	// this one is abandoned before the subscription exists.
	if err := s.db.Q.SetSubscriptionCustomer(ctx, &db.SetSubscriptionCustomerParams{
		WorkspaceID: workspaceID,
		CustomerID:  customer.ID,
	}); err != nil {
		slog.Warn("failed to record customer mapping", "error", err, "workspace_id", workspaceID)
	}
	return customer.ID, nil
}

// Portal creates a Stripe Customer Portal session for the workspace's customer.
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
		Statuses:    entitlement.ActiveStatuses,
		Sources:     stripeSources,
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
	s.upsertSubscription(ctx, workspaceID, remote)
}

// SyncAll reconciles every Stripe-managed row. Runs at startup.
func (s *Stripe) SyncAll(ctx context.Context) error {
	subs, err := s.db.Q.ListProviderSubscriptions(ctx, stripeSources)
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
		Statuses: entitlement.ActiveStatuses,
		Sources:  stripeSources,
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

// flexPrices returns the configured Flex plan price IDs, trimmed of whitespace.
func (s *Stripe) flexPrices() []string {
	var out []string
	for id := range strings.SplitSeq(s.FlexPriceIDs, ",") {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}

func (s *Stripe) upsertSubscription(
	ctx context.Context,
	workspaceID string,
	sub *stripe.Subscription,
) {
	if err := s.db.Q.UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
		WorkspaceID:       workspaceID,
		Source:            "stripe",
		Plan:              entitlement.PlanFlex,
		Status:            string(mapStatus(sub.Status)),
		CustomerID:        sub.Customer.ID,
		SubscriptionID:    sub.ID,
		CurrentPeriodEnd:  periodEnd(sub),
		CancelAtPeriodEnd: sub.CancelAtPeriodEnd,
	}); err != nil {
		slog.Warn("failed to upsert subscription", "error", err, "workspace_id", workspaceID)
	}
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

func usageFor(stats *db.GetWorkspaceStatsRow, r entitlement.Resource) int64 {
	switch r {
	case entitlement.ResourceMembers:
		return stats.MemberCount
	case entitlement.ResourceServiceAccounts:
		return stats.ServiceAccountCount
	case entitlement.ResourceTargets:
		return stats.TargetCount
	case entitlement.ResourceTeams:
		return stats.TeamCount
	case entitlement.ResourceCas:
		return stats.CaCount
	}
	return -1
}
