package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	stripe "github.com/stripe/stripe-go/v86"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
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
	client    *stripe.Client
	db        *db.Connection
	returnURL string

	ProPriceID    string `env:"STRIPE_PRO_PRICE_ID"`
	SecretKey     string `env:"STRIPE_SECRET_KEY"`
	WebhookSecret string `env:"STRIPE_WEBHOOK_SECRET"`
}

// New returns nil on a self-hosted server, see newStripe.
func New(ctx context.Context, conn *db.Connection, baseURL string, saas bool) (*Stripe, error) {
	s, err := newStripe(conn, baseURL, saas)
	if err != nil || s == nil {
		return nil, err
	}
	go s.reconcile(ctx)
	return s, nil
}

// newStripe never guesses the mode. Hosted needs every setting, self-hosted with any of them fails the start.
func newStripe(conn *db.Connection, returnURL string, saas bool) (*Stripe, error) {
	s, err := env.ParseAs[Stripe]()
	if err != nil {
		return nil, err
	}
	complete := s.SecretKey != "" && s.WebhookSecret != "" && s.ProPriceID != ""
	unset := s.SecretKey == "" && s.WebhookSecret == "" && s.ProPriceID == ""
	switch {
	case saas && !complete:
		return nil, errors.New("NOKKU_SAAS needs STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET and STRIPE_PRO_PRICE_ID")
	case !saas && !unset:
		return nil, errors.New(
			"STRIPE_* is set on a self-hosted server, set NOKKU_SAAS=true for the hosted service or remove it",
		)
	case !saas:
		return nil, nil
	}

	s.db = conn
	s.returnURL = returnURL
	s.client = stripe.NewClient(s.SecretKey)
	return &s, nil
}

// Checkout starts at the current member count. The paid quantity becomes the seat cap.
func (s *Stripe) Checkout(ctx context.Context, workspaceID, email string) (string, error) {
	if s == nil {
		return "", errDisabled
	}
	if workspaceID == "" {
		return "", errors.New("missing workspace ID")
	}

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
			AdjustableQuantity: &stripe.CheckoutSessionCreateLineItemAdjustableQuantityParams{
				Enabled: new(true),
				Minimum: new(quantity),
				Maximum: new(int64(maxCheckoutSeats)),
			},
		}},
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

// The helpers below use system transactions, Stripe flows run outside a tenant scope.

func (s *Stripe) subscription(
	ctx context.Context,
	workspaceID string,
) (*db.WorkspaceSubscription, error) {
	var sub *db.WorkspaceSubscription
	if err := s.db.SysTx(ctx, func(q *db.Queries) (err error) {
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
	if err := s.db.SysTx(ctx, func(q *db.Queries) (err error) {
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

	if err := s.db.SysTx(ctx, func(q *db.Queries) error {
		return q.SetSubscriptionCustomer(ctx, &db.SetSubscriptionCustomerParams{
			WorkspaceID: workspaceID,
			CustomerID:  customer.ID,
		})
	}); err != nil {
		slog.Warn("failed to record customer mapping", "error", err, "workspace_id", workspaceID)
	}
	return customer.ID, nil
}

// Portal is where seats are bought, so the Stripe portal configuration must allow quantity updates.
func (s *Stripe) Portal(ctx context.Context, workspaceID string) (string, error) {
	if s == nil {
		return "", errDisabled
	}
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
	if errors.Is(err, entitlement.ErrNoSubscription) {
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
	if err != nil && !errors.Is(err, entitlement.ErrNoSubscription) {
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

	var seats int64
	if remote.Items != nil && len(remote.Items.Data) > 0 {
		seats = remote.Items.Data[0].Quantity
	}
	var endedAt *time.Time
	if remote.EndedAt != 0 {
		endedAt = new(time.Unix(remote.EndedAt, 0).UTC())
	}
	// The plan stays on an ended row, the retention hold reads it.
	err = s.db.SysTx(ctx, func(q *db.Queries) error {
		return q.UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
			WorkspaceID:       workspaceID,
			Source:            "stripe",
			Plan:              entitlement.PlanPro,
			Status:            string(mapStatus(remote.Status)),
			CustomerID:        remote.Customer.ID,
			SubscriptionID:    remote.ID,
			CurrentPeriodEnd:  periodEnd(remote),
			CancelAtPeriodEnd: remote.CancelAtPeriodEnd,
			Seats:             seats,
			EndedAt:           endedAt,
		})
	})
	// The workspace was deleted, there is nothing left to mirror.
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok &&
		pgErr.Code == pgerrcode.ForeignKeyViolation {
		return nil
	}
	return err
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
	var subs []*db.WorkspaceSubscription
	if err := s.db.SysTx(ctx, func(q *db.Queries) (err error) {
		subs, err = q.ListProviderSubscriptions(ctx, []string{"stripe"})
		return err
	}); err != nil {
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
	var count int64
	if err := s.db.SysTx(ctx, func(q *db.Queries) (err error) {
		count, err = q.CountActiveUsers(ctx, workspaceID)
		return err
	}); err != nil {
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
