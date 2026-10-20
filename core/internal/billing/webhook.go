package billing

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/stripe/stripe-go/v87/webhook"
)

const maxWebhookBody = 2 << 20

// WebhookHandler is only registered on the hosted service.
func (s *Stripe) WebhookHandler() http.Handler {
	return http.HandlerFunc(s.webhook)
}

func (s *Stripe) webhook(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusRequestEntityTooLarge)
		return
	}

	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), s.WebhookSecret)
	if err != nil {
		slog.Warn("Stripe webhook signature verification failed", "error", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	switch string(event.Type) {
	case "customer.subscription.created",
		"customer.subscription.updated",
		"customer.subscription.deleted":
		// Events can arrive late or out of order, so the payload only says which subscription to read again.
		var sub struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil || sub.ID == "" {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		// A 500 makes Stripe retry, so a failed write is not lost.
		if err := s.sync(r.Context(), sub.ID); err != nil {
			slog.Error("failed to apply Stripe subscription event", "error", err,
				"event_type", event.Type, "subscription_id", sub.ID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

	default:
		// Unhandled event types are expected, Stripe sends everything subscribed.
	}

	w.WriteHeader(http.StatusOK)
}
