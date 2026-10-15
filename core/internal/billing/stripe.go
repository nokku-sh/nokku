package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	stripe "github.com/stripe/stripe-go/v87"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

var (
	ErrActiveSubscription = errors.New("workspace already has an active subscription")
	errDisabled           = errors.New("billing provider is not configured")
)

const (
	// minBillableSeats is the pricing floor.
	minBillableSeats = 5
	// Stripe defaults the checkout quantity picker to 99.
	maxCheckoutSeats = 10000
)

// Stripe moves money and never decides what a workspace may do. A nil Stripe is a self-hosted server.
type Stripe struct {
	client *stripe.Client
	db     *db.Connection

	ProMonthlyPriceID string `env:"STRIPE_PRO_MONTHLY_PRICE_ID"`
	ProYearlyPriceID  string `env:"STRIPE_PRO_YEARLY_PRICE_ID"`
	SecretKey         string `env:"STRIPE_SECRET_KEY"`
	WebhookSecret     string `env:"STRIPE_WEBHOOK_SECRET"`
}

// New returns nil on a self-hosted server, see newStripe.
func New(ctx context.Context, conn *db.Connection, saas bool) (*Stripe, error) {
	s, err := newStripe(conn, saas)
	if err != nil || s == nil {
		return nil, err
	}
	go s.reconcile(ctx)
	return s, nil
}

// newStripe never guesses the mode. Hosted needs every setting, self-hosted with any of them fails the start.
func newStripe(conn *db.Connection, saas bool) (*Stripe, error) {
	s, err := env.ParseAs[Stripe]()
	if err != nil {
		return nil, err
	}
	settings := []string{s.SecretKey, s.WebhookSecret, s.ProMonthlyPriceID, s.ProYearlyPriceID}
	complete := !slices.Contains(settings, "")
	unset := strings.Join(settings, "") == ""
	switch {
	case saas && !complete:
		return nil, errors.New(
			"NOKKU_SAAS needs STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRO_MONTHLY_PRICE_ID and STRIPE_PRO_YEARLY_PRICE_ID",
		)
	case !saas && !unset:
		return nil, errors.New(
			"STRIPE_* is set on a self-hosted server, set NOKKU_SAAS=true for the hosted service or remove it",
		)
	case !saas:
		return nil, nil
	}

	s.db = conn
	s.client = stripe.NewClient(s.SecretKey)
	return &s, nil
}

// Checkout starts at the current member count. The paid quantity becomes the seat cap.
func (s *Stripe) Checkout(ctx context.Context, ws actor.Workspace, email string, yearly bool) (string, error) {
	if s == nil {
		return "", errDisabled
	}
	workspaceID := ws.ID
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}

	if _, err := s.activeSubscription(ctx, workspaceID); err == nil {
		return "", ErrActiveSubscription
	}

	quantity, err := s.billableSeats(ctx, workspaceID)
	if err != nil {
		return "", err
	}

	price := s.ProMonthlyPriceID
	if yearly {
		price = s.ProYearlyPriceID
	}
	params := &stripe.CheckoutSessionCreateParams{
		Mode: stripe.String(stripe.CheckoutSessionModeSubscription),
		// Stripe is the merchant of record and handles tax, so the session must not set automatic_tax or tax_id_collection.
		ManagedPayments: &stripe.CheckoutSessionCreateManagedPaymentsParams{Enabled: new(true)},
		LineItems: []*stripe.CheckoutSessionCreateLineItemParams{{
			Price:    stripe.String(price),
			Quantity: new(quantity),
			AdjustableQuantity: &stripe.CheckoutSessionCreateLineItemAdjustableQuantityParams{
				Enabled: new(true),
				Minimum: new(quantity),
				Maximum: new(int64(maxCheckoutSeats)),
			},
		}},
		SuccessURL:        stripe.String(billingPage(ws)),
		CancelURL:         stripe.String(billingPage(ws)),
		ClientReferenceID: stripe.String(workspaceID),
		SubscriptionData: &stripe.CheckoutSessionCreateSubscriptionDataParams{
			Metadata: map[string]string{"workspace_id": workspaceID},
		},
	}
	// A workspace that paid before keeps its customer, Checkout makes one for a new workspace.
	if sub, err := s.db.Sys().GetSubscription(ctx, workspaceID); err == nil && sub.CustomerID != "" {
		params.Customer = stripe.String(sub.CustomerID)
	} else if email != "" {
		params.CustomerEmail = stripe.String(email)
	}

	session, err := s.client.V1CheckoutSessions.Create(ctx, params)
	if err != nil {
		return "", fmt.Errorf("create checkout session: %w", err)
	}
	return session.URL, nil
}

// activeSubscription is the row Stripe is paid for, pgx.ErrNoRows without one. Stripe flows run outside a tenant scope.
func (s *Stripe) activeSubscription(
	ctx context.Context,
	workspaceID string,
) (*db.WorkspaceSubscription, error) {
	sub, err := s.db.Sys().GetSubscription(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	if sub.Source != "stripe" || !entitlement.Active(sub.Status) {
		return nil, pgx.ErrNoRows
	}
	return sub, nil
}

// Portal is where seats are bought, so the Stripe portal configuration must allow quantity updates.
func (s *Stripe) Portal(ctx context.Context, ws actor.Workspace) (string, error) {
	if s == nil {
		return "", errDisabled
	}
	if ws.ID == "" {
		return "", errors.New("missing workspace ID")
	}
	sub, err := s.db.Sys().GetSubscription(ctx, ws.ID)
	if err != nil || sub.CustomerID == "" {
		return "", errors.New("no Stripe customer for this workspace")
	}

	session, err := s.client.V1BillingPortalSessions.Create(
		ctx,
		&stripe.BillingPortalSessionCreateParams{
			Customer:  stripe.String(sub.CustomerID),
			ReturnURL: stripe.String(billingPage(ws)),
		},
	)
	if err != nil {
		return "", fmt.Errorf("create portal session: %w", err)
	}
	return session.URL, nil
}

// billingPage is on the workspace host, the hosted root host has no workspace to land in.
func billingPage(ws actor.Workspace) string {
	return ws.BaseURL + "/settings/billing"
}

func (s *Stripe) Cancel(
	ctx context.Context,
	workspaceID string,
	immediate bool,
	reason string,
) error {
	if s == nil {
		return errDisabled
	}
	if workspaceID == "" {
		return errors.New("missing workspace ID")
	}
	sub, err := s.activeSubscription(ctx, workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // free workspaces have nothing to cancel
	}
	if err != nil {
		return fmt.Errorf("get active subscription: %w", err)
	}
	if sub.SubscriptionID == "" {
		return nil // no Stripe subscription to cancel
	}

	if immediate {
		_, err = s.client.V1Subscriptions.Cancel(ctx, sub.SubscriptionID, nil)
	} else {
		params := &stripe.SubscriptionUpdateParams{CancelAtPeriodEnd: new(true)}
		if reason != "" {
			params.CancellationDetails = &stripe.SubscriptionUpdateCancellationDetailsParams{
				Comment: stripe.String(reason),
			}
		}
		_, err = s.client.V1Subscriptions.Update(ctx, sub.SubscriptionID, params)
	}
	if err != nil {
		return err
	}
	// The webhook delivers the same state, this only makes it show at once.
	if err := s.sync(ctx, sub.SubscriptionID); err != nil {
		slog.Warn("failed to sync cancelled subscription", "error", err, "workspace_id", workspaceID)
	}
	return nil
}

// sync is the only writer of subscription state, so the webhook, cancel and reconcile can never disagree.
func (s *Stripe) sync(ctx context.Context, subscriptionID string) error {
	remote, err := s.client.V1Subscriptions.Retrieve(
		ctx, subscriptionID,
		&stripe.SubscriptionRetrieveParams{},
	)
	if err != nil {
		return fmt.Errorf("fetch subscription: %w", err)
	}
	// License subscriptions carry no workspace, the license worker owns them.
	workspaceID := remote.Metadata["workspace_id"]
	if workspaceID == "" {
		return nil
	}

	active, err := s.activeSubscription(ctx, workspaceID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && active.SubscriptionID != "" && active.SubscriptionID != remote.ID {
		// A late event for an old subscription must not downgrade the live one.
		if remote.Status == stripe.SubscriptionStatusCanceled {
			return nil
		}
		// The stored one may have ended without us hearing of it yet.
		live, err := s.client.V1Subscriptions.Retrieve(
			ctx, active.SubscriptionID,
			&stripe.SubscriptionRetrieveParams{},
		)
		if err != nil {
			return fmt.Errorf("fetch stored subscription: %w", err)
		}
		if live.Status != stripe.SubscriptionStatusCanceled {
			// Backstop so a workspace never ends up with two active subscriptions.
			slog.Warn("cancelling duplicate subscription",
				"workspace_id", workspaceID, "keep", active.SubscriptionID, "duplicate", remote.ID)
			if _, err := s.client.V1Subscriptions.Cancel(ctx, remote.ID, nil); err != nil {
				return fmt.Errorf("cancel duplicate subscription: %w", err)
			}
			return nil
		}
	}

	remote, err = s.trueUp(ctx, workspaceID, remote)
	if err != nil {
		return err
	}

	var seats int64
	if remote.Items != nil && len(remote.Items.Data) > 0 {
		seats = remote.Items.Data[0].Quantity
	}
	var endedAt *time.Time
	if remote.EndedAt != 0 {
		endedAt = new(time.Unix(remote.EndedAt, 0).UTC())
	}
	// The plan stays on an ended row, the retention hold reads it.
	err = s.db.Sys().UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
		WorkspaceID: workspaceID,
		Source:      "stripe",
		Plan:        entitlement.PlanPro,
		// Stripe's own status, entitlement.Active reads it.
		Status:            string(remote.Status),
		CustomerID:        remote.Customer.ID,
		SubscriptionID:    remote.ID,
		CurrentPeriodEnd:  periodEnd(remote),
		CancelAtPeriodEnd: remote.CancelAtPeriodEnd,
		Seats:             seats,
		EndedAt:           endedAt,
	})
	// The workspace was deleted, there is nothing left to mirror.
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok &&
		pgErr.Code == pgerrcode.ForeignKeyViolation {
		return nil
	}
	return err
}

// trueUp raises the paid seats to the member count, or dropping seats in the portal would keep members for free.
// The update fires a webhook that syncs again, and that one finds nothing to raise.
func (s *Stripe) trueUp(
	ctx context.Context,
	workspaceID string,
	sub *stripe.Subscription,
) (*stripe.Subscription, error) {
	// A past due customer is not charged more on top.
	if sub.Status != stripe.SubscriptionStatusActive || sub.Items == nil || len(sub.Items.Data) == 0 {
		return sub, nil
	}
	item := sub.Items.Data[0]
	want, err := s.billableSeats(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	if item.Quantity >= want {
		return sub, nil
	}
	slog.Info("raising seats to the member count",
		"workspace_id", workspaceID, "paid", item.Quantity, "billable", want)
	updated, err := s.client.V1Subscriptions.Update(ctx, sub.ID, &stripe.SubscriptionUpdateParams{
		Items:             []*stripe.SubscriptionUpdateItemParams{{ID: stripe.String(item.ID), Quantity: new(want)}},
		ProrationBehavior: new("always_invoice"),
	})
	if err != nil {
		return nil, fmt.Errorf("raise seats: %w", err)
	}
	return updated, nil
}

// reconcile lets missed webhooks self-heal, 5 minutes after start and then every 12 hours.
func (s *Stripe) reconcile(ctx context.Context) {
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := s.syncAll(ctx); err != nil {
			slog.Error("failed to reconcile subscriptions", "error", err)
		}
		timer.Reset(12 * time.Hour)
	}
}

func (s *Stripe) syncAll(ctx context.Context) error {
	subs, err := s.db.Sys().ListProviderSubscriptions(ctx)
	if err != nil {
		return err
	}
	for _, sub := range subs {
		if err := s.sync(ctx, sub.SubscriptionID); err != nil {
			slog.Warn("failed to sync subscription", "error", err, "workspace_id", sub.WorkspaceID)
		}
	}
	return nil
}

func (s *Stripe) billableSeats(ctx context.Context, workspaceID string) (int64, error) {
	count, err := s.db.Sys().CountActiveUsers(ctx, workspaceID)
	if err != nil {
		return 0, fmt.Errorf("count users for checkout: %w", err)
	}
	return max(count, minBillableSeats), nil
}

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
