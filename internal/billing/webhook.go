package billing

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	stripe "github.com/stripe/stripe-go/v86"
	"github.com/stripe/stripe-go/v86/webhook"

	"github.com/nokku-sh/nokku/internal/db"
)

func (s *Stripe) WebhookHandler() http.Handler {
	return http.HandlerFunc(s.webhook)
}

func (s *Stripe) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), s.WebhookSecret)
	if err != nil {
		slog.Warn("Stripe webhook signature verification failed", "error", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	switch string(event.Type) {
	case "customer.subscription.created",
		"customer.subscription.updated",
		"customer.subscription.deleted":
		var sub stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		s.handleSubscription(ctx, &sub)

	default:
		slog.Debug("ignoring unhandled Stripe webhook event", "event_type", event.Type)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Stripe) handleSubscription(ctx context.Context, sub *stripe.Subscription) {
	workspaceID := sub.Metadata["workspace_id"]
	if workspaceID == "" {
		return
	}

	if sub.Status == stripe.SubscriptionStatusCanceled {
		if err := s.db.Q.UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
			WorkspaceID:       workspaceID,
			Source:            "stripe",
			Plan:              "",
			Status:            string(StatusInactive),
			CustomerID:        sub.Customer.ID,
			SubscriptionID:    sub.ID,
			CurrentPeriodEnd:  periodEnd(sub),
			CancelAtPeriodEnd: sub.CancelAtPeriodEnd,
		}); err != nil {
			slog.Warn("failed to clear subscription", "error", err, "workspace_id", workspaceID)
		}
		return
	}

	// Backstop for the one-subscription-per-workspace rule: cancel a newcomer
	// if the workspace already holds a different active subscription, so a
	// tenant never ends up with two.
	if existing, err := s.db.Q.GetActiveSubscription(ctx, &db.GetActiveSubscriptionParams{
		WorkspaceID: workspaceID,
		Statuses:    ActiveStatuses,
		Sources:     []string{"stripe"},
	}); err == nil && existing.SubscriptionID != "" && existing.SubscriptionID != sub.ID {
		slog.Warn("cancelling duplicate subscription",
			"workspace_id", workspaceID, "keep", existing.SubscriptionID, "duplicate", sub.ID)
		if _, err := s.client.V1Subscriptions.Cancel(ctx, sub.ID, nil); err != nil {
			slog.Warn("failed to cancel duplicate subscription", "error", err,
				"workspace_id", workspaceID, "subscription_id", sub.ID)
		}
		return
	}

	if err := s.db.Q.UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
		WorkspaceID:       workspaceID,
		Source:            "stripe",
		Plan:              PlanFlex,
		Status:            string(mapStatus(sub.Status)),
		CustomerID:        sub.Customer.ID,
		SubscriptionID:    sub.ID,
		CurrentPeriodEnd:  periodEnd(sub),
		CancelAtPeriodEnd: sub.CancelAtPeriodEnd,
	}); err != nil {
		slog.Warn("failed to upsert subscription", "error", err, "workspace_id", workspaceID)
	}
}
