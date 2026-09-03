package billing

import (
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v86"

	"github.com/nokku-sh/nokku/internal/entitlement"
)

func TestMapStatus(t *testing.T) {
	cases := map[stripe.SubscriptionStatus]entitlement.Status{
		stripe.SubscriptionStatusActive:            entitlement.StatusActive,
		stripe.SubscriptionStatusTrialing:          entitlement.StatusTrialing,
		stripe.SubscriptionStatusPastDue:           entitlement.StatusPastDue,
		stripe.SubscriptionStatusCanceled:          entitlement.StatusInactive,
		stripe.SubscriptionStatusUnpaid:            entitlement.StatusInactive,
		stripe.SubscriptionStatusPaused:            entitlement.StatusInactive,
		stripe.SubscriptionStatusIncomplete:        entitlement.StatusInactive,
		stripe.SubscriptionStatusIncompleteExpired: entitlement.StatusInactive,
	}
	for in, want := range cases {
		if got := mapStatus(in); got != want {
			t.Errorf("mapStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPeriodEnd(t *testing.T) {
	if got := periodEnd(&stripe.Subscription{}); got != nil {
		t.Fatalf("expected nil period end for empty subscription, got %v", got)
	}

	now := time.Now().UTC().Truncate(time.Second)
	sub := &stripe.Subscription{
		Items: &stripe.SubscriptionItemList{
			Data: []*stripe.SubscriptionItem{{CurrentPeriodEnd: now.Unix()}},
		},
	}
	got := periodEnd(sub)
	if got == nil || !got.Equal(now) {
		t.Fatalf("periodEnd = %v, want %v", got, now)
	}
}
