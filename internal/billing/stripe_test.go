package billing

import (
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v86"
)

func TestMapStatus(t *testing.T) {
	cases := map[stripe.SubscriptionStatus]Status{
		stripe.SubscriptionStatusActive:            StatusActive,
		stripe.SubscriptionStatusTrialing:          StatusTrialing,
		stripe.SubscriptionStatusPastDue:           StatusPastDue,
		stripe.SubscriptionStatusCanceled:          StatusInactive,
		stripe.SubscriptionStatusUnpaid:            StatusInactive,
		stripe.SubscriptionStatusPaused:            StatusInactive,
		stripe.SubscriptionStatusIncomplete:        StatusInactive,
		stripe.SubscriptionStatusIncompleteExpired: StatusInactive,
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
