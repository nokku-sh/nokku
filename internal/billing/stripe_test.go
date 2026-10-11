package billing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	stripe "github.com/stripe/stripe-go/v86"
)

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

// Settings that do not fit NOKKU_SAAS fail the start, a hosted service must never come up self-hosted.
func TestNewStripeNeverGuessesTheMode(t *testing.T) {
	all := map[string]string{
		"STRIPE_SECRET_KEY": "sk_test", "STRIPE_WEBHOOK_SECRET": "whsec", "STRIPE_PRO_PRICE_ID": "price",
	}
	cases := map[string]struct {
		saas    bool
		env     map[string]string
		enabled bool
		wantErr string
	}{
		"self-hosted":           {},
		"hosted":                {saas: true, env: all, enabled: true},
		"hosted without stripe": {saas: true, wantErr: "NOKKU_SAAS needs"},
		"hosted with a setting missing": {
			saas:    true,
			env:     map[string]string{"STRIPE_SECRET_KEY": "sk_test"},
			wantErr: "NOKKU_SAAS needs",
		},
		"self-hosted with stripe": {env: all, wantErr: "self-hosted"},
		"self-hosted with one stripe key": {
			env:     map[string]string{"STRIPE_PRO_PRICE_ID": "price"},
			wantErr: "self-hosted",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for key := range all {
				t.Setenv(key, tc.env[key])
			}
			s, err := newStripe(nil, "https://nokku.test", tc.saas)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.enabled, s != nil)
		})
	}
}

// A call that missed the mode gate gets an error, not a panic.
func TestNilStripeIsDisabled(t *testing.T) {
	var s *Stripe
	_, err := s.Checkout(t.Context(), "ws", "owner@example.com")
	require.ErrorIs(t, err, errDisabled)
	_, err = s.Portal(t.Context(), "ws")
	require.ErrorIs(t, err, errDisabled)
	require.ErrorIs(t, s.Cancel(t.Context(), "ws", true, ""), errDisabled)
}
