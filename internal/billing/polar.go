package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	"github.com/nokku-sh/nokku/internal/meta"
	polargo "github.com/polarsource/polar-go"
	"github.com/polarsource/polar-go/models/components"
	"github.com/polarsource/polar-go/models/operations"
)

// Polar implements Provider for polar.sh.
type Polar struct {
	client        *polargo.Polar
	db            *db.Connection
	returnURL     string
	Token         string `env:"POLAR_ACCESS_TOKEN"`
	WebhookSecret string `env:"POLAR_WEBHOOK_SECRET"`
	FlexPlanID    string `env:"POLAR_FLEX_PLAN_ID"`
	Server        string `env:"POLAR_SERVER"         envDefault:"production"`
}

var polarSources = []string{"polar", ""}

// NewPolar returns nil (no error) when POLAR_ACCESS_TOKEN is unset (billing
// disabled). A set token missing FlexPlanID is a config error.
func NewPolar(conn *db.Connection, returnURL string) (*Polar, error) {
	p, err := env.ParseAs[Polar]()
	if err != nil {
		return nil, err
	}
	if p.Token == "" || p.WebhookSecret == "" || p.FlexPlanID == "" {
		return nil, nil // billing disabled
	}

	p.db = conn
	p.returnURL = returnURL
	p.client = polargo.New(
		polargo.WithServer(p.Server),
		polargo.WithSecurity(p.Token),
	)
	return &p, nil
}

// Sync fetches Polar state for one workspace and upserts the local row.
func (p *Polar) Sync(ctx context.Context, workspaceID string) {
	// Don't sync if the workspace has a manual subscription. (e.g. enterprise)
	existingSub, err := p.db.Q.GetSubscription(ctx, workspaceID)
	if err == nil && existingSub.Source != "polar" && existingSub.Source != "" {
		slog.Debug("skipping polar sync for manual subscription", "workspace_id", workspaceID)
		return
	}

	res, err := p.client.Subscriptions.List(
		ctx,
		operations.SubscriptionsListRequest{
			ExternalCustomerID: &operations.ExternalCustomerIDFilter{Str: &workspaceID},
			Limit:              new(int64),
		},
	)
	if err == nil && res.ListResourceSubscription != nil &&
		len(res.ListResourceSubscription.Items) > 0 {
		p.upsertSubscription(ctx, workspaceID, res.ListResourceSubscription.Items[0])
		return
	}

	// No subscription in Polar — mark inactive so workspace falls back to community.
	if err := p.db.Q.UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
		WorkspaceID: workspaceID,
		Source:      "polar",
		Plan:        "",
		Status:      string(entitlement.StatusInactive),
		Metadata:    map[string]any{},
	}); err != nil {
		slog.Debug("failed to clear subscription", "err", err)
	}
}

// SyncAll reconciles every polar-managed row. Runs at startup.
func (p *Polar) SyncAll(ctx context.Context) error {
	subs, err := p.db.Q.ListProviderSubscriptions(ctx, polarSources)
	if err != nil {
		return err
	}
	for _, sub := range subs {
		p.Sync(ctx, sub.WorkspaceID)
	}
	if len(subs) > 0 {
		slog.Info("reconciled subscriptions with Polar", "count", len(subs))
	}
	return nil
}

func (p *Polar) upsertSubscription(
	ctx context.Context,
	workspaceID string,
	event components.Subscription,
) {
	status := mapStatus(event.Status)

	metadata := map[string]any{}
	if status.GrantsAccess() {
		metadata = MergeMetadata(event.Product.Metadata, event.Metadata)
	}
	if err := p.db.Q.UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
		WorkspaceID:       workspaceID,
		Source:            "polar",
		Plan:              p.planForProduct(event.Product.ID),
		Status:            string(status),
		CustomerID:        event.Customer.ID,
		SubscriptionID:    event.ID,
		ProductID:         event.Product.ID,
		ProductName:       event.Product.Name,
		Metadata:          metadata,
		CurrentPeriodEnd:  &event.CurrentPeriodEnd,
		CancelAtPeriodEnd: event.CancelAtPeriodEnd,
	}); err != nil {
		slog.Debug("failed to upsert synced subscription", "err", err)
	}
}

func (p *Polar) Portal(ctx context.Context, workspaceID string) (string, error) {
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}
	res, err := p.client.CustomerSessions.Create(
		ctx,
		operations.CustomerSessionsCreateCustomerSessionCreate{
			CustomerSessionCustomerExternalIDCreate: &components.CustomerSessionCustomerExternalIDCreate{
				ExternalCustomerID: workspaceID,
				ReturnURL:          &p.returnURL,
			},
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create customer session: %w", err)
	}
	if res.CustomerSession == nil {
		return "", errors.New("customer session is nil")
	}
	return res.CustomerSession.CustomerPortalURL, nil
}

func (p *Polar) Checkout(ctx context.Context, workspaceID string) (string, error) {
	userID := meta.UserIDFromContext(ctx)
	if userID == "" {
		return "", errors.New("missing user ID")
	}
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}

	user, err := p.db.Q.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}

	res, err := p.client.Checkouts.Create(ctx, components.CheckoutCreate{
		ExternalCustomerID: &workspaceID,
		Products:           []string{p.FlexPlanID},
		CustomerEmail:      &user.Email,
		ReturnURL:          new(p.returnURL + "/profile/billing"),
		SuccessURL:         new(p.returnURL + "/profile/billing"),
	})
	if err != nil {
		// Customer email might be invalid, try without
		res, err = p.client.Checkouts.Create(ctx, components.CheckoutCreate{
			ExternalCustomerID: &workspaceID,
			Products:           []string{p.FlexPlanID},
			ReturnURL:          new(p.returnURL + "/profile/billing"),
			SuccessURL:         new(p.returnURL + "/profile/billing"),
		})
		if err != nil {
			return "", errors.New("failed to create checkout link")
		}
	}

	return res.Checkout.URL, nil
}

func (p *Polar) Cancel(
	ctx context.Context,
	workspaceID string,
	immediate bool,
	reason string,
) error {
	if workspaceID == "" {
		return errors.New("missing workspace ID")
	}

	sub, err := p.db.Q.GetActiveSubscription(ctx, &db.GetActiveSubscriptionParams{
		WorkspaceID: workspaceID,
		Statuses:    entitlement.ActiveStatuses,
		Sources:     polarSources,
	})
	if err != nil {
		return fmt.Errorf("get active subscription: %w", err)
	}
	if sub.SubscriptionID == "" {
		return nil // No active subscription
	}

	if immediate {
		_, err = p.client.Subscriptions.Revoke(ctx, sub.SubscriptionID)
	} else {
		_, err = p.client.Subscriptions.Update(
			ctx,
			sub.SubscriptionID,
			components.SubscriptionUpdate{
				SubscriptionCancel: &components.SubscriptionCancel{
					CancelAtPeriodEnd:           true,
					CustomerCancellationComment: &reason,
				},
			},
			nil,
		)
	}
	if err != nil {
		return err
	}
	p.Sync(ctx, workspaceID)
	return nil
}

// SyncUsage reports daily usage gauges for metered billing.
func (p *Polar) SyncUsage(ctx context.Context) error {
	subscriptions, err := p.db.Q.ListActiveSubscriptions(ctx, &db.ListActiveSubscriptionsParams{
		Statuses: entitlement.ActiveStatuses,
		Sources:  polarSources,
	})
	if err != nil {
		return err
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	var events []components.Events

	for _, sub := range subscriptions {
		stats, err := p.db.Q.GetWorkspaceStats(ctx, sub.WorkspaceID)
		if err != nil {
			continue
		}

		metadata := make(map[string]components.EventMetadataInput)
		metadata["members"] = components.CreateEventMetadataInputInteger(stats.MemberCount)
		metadata["targets"] = components.CreateEventMetadataInputInteger(stats.TargetCount)
		metadata["service_accounts"] = components.CreateEventMetadataInputInteger(
			stats.ServiceAccountCount,
		)

		idempotencyKey := fmt.Sprintf("usage_%s_%s", sub.WorkspaceID, today.Format(time.DateOnly))

		events = append(events, components.CreateEventsEventCreateExternalCustomer(
			components.EventCreateExternalCustomer{
				Name:               "nokku_usage",
				ExternalCustomerID: sub.WorkspaceID,
				ExternalID:         &idempotencyKey,
				Timestamp:          &today,
				Metadata:           metadata,
			},
		))
	}

	if len(events) == 0 {
		return nil
	}

	_, err = p.client.Events.Ingest(ctx, components.EventsIngest{Events: events})
	return err
}

func (p *Polar) planForProduct(productID string) string {
	switch productID {
	case p.FlexPlanID:
		return entitlement.PlanFlex
	default:
		slog.Warn("unknown Polar product, falling back to community plan", "product_id", productID)
		return entitlement.PlanCommunity
	}
}

func mapStatus(s components.SubscriptionStatus) entitlement.Status {
	switch s {
	case components.SubscriptionStatusActive:
		return entitlement.StatusActive
	case components.SubscriptionStatusTrialing:
		return entitlement.StatusTrialing
	case components.SubscriptionStatusPastDue:
		return entitlement.StatusPastDue
	case components.SubscriptionStatusIncomplete,
		components.SubscriptionStatusIncompleteExpired,
		components.SubscriptionStatusCanceled,
		components.SubscriptionStatusUnpaid:
		return entitlement.StatusInactive
	}
	return entitlement.StatusInactive
}
