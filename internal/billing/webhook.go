package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/polarsource/polar-go/models/components"
)

const webhookTolerance = 5 * time.Minute

func (p *Polar) WebhookHandler() http.Handler {
	return http.HandlerFunc(p.webhook)
}

func (p *Polar) webhook(w http.ResponseWriter, r *http.Request) {
	if p.WebhookSecret == "" {
		slog.Error("polar webhook received but POLAR_WEBHOOK_SECRET is not set")
		http.Error(w, "webhook is not configured", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	if err := verifySignature(p.WebhookSecret, r.Header, body, time.Now()); err != nil {
		slog.Warn("polar webhook signature verification failed", "err", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var event struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid payload format", http.StatusBadRequest)
		return
	}

	switch event.Type {
	case "subscription.created",
		"subscription.updated",
		"subscription.active",
		"subscription.canceled",
		"subscription.uncanceled",
		"subscription.revoked":
		var sub components.Subscription
		if err := json.Unmarshal(event.Data, &sub); err != nil {
			http.Error(w, "invalid payload data", http.StatusBadRequest)
			return
		}
		if sub.Customer.ExternalID == nil {
			http.Error(w, "invalid payload data", http.StatusBadRequest)
			return
		}
		p.upsertSubscription(r.Context(), *sub.Customer.ExternalID, sub)

	default:
		slog.Debug("ignoring unhandled polar webhook event", "type", event.Type)
	}

	w.WriteHeader(http.StatusOK)
}

// verifySignature checks a Standard Webhooks v1 signature.
func verifySignature(secret string, h http.Header, body []byte, now time.Time) error {
	id := h.Get("Webhook-Id")
	timestamp := h.Get("Webhook-Timestamp")
	signatures := h.Get("Webhook-Signature")
	if id == "" || timestamp == "" || signatures == "" {
		return errors.New("missing webhook headers")
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid webhook timestamp: %w", err)
	}
	if math.Abs(now.Sub(time.Unix(ts, 0)).Seconds()) > webhookTolerance.Seconds() {
		return errors.New("webhook timestamp outside tolerance")
	}

	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return fmt.Errorf("invalid webhook secret: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "." + string(body)))
	expected := mac.Sum(nil)

	for part := range strings.FieldsSeq(signatures) {
		version, encoded, ok := strings.Cut(part, ",")
		if !ok || version != "v1" {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		if hmac.Equal(sig, expected) {
			return nil
		}
	}
	return errors.New("no matching signature")
}
