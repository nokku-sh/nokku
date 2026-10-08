//go:build integration

package billing_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	stripe "github.com/stripe/stripe-go/v86"
	"github.com/stripe/stripe-go/v86/webhook"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	"github.com/nokku-sh/nokku/internal/integration/testenv"
)

const webhookSecret = "whsec_test"

func TestMain(m *testing.M) {
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}

type remoteSub struct {
	status   string
	seats    int64
	endedAt  int64
	cancelAt bool
}

// fakeStripe is the hosted service on a Stripe that serves the two
// subscription calls a sync makes.
type fakeStripe struct {
	billing *billing.Stripe
	conn    *db.Connection

	mu          sync.Mutex
	workspaceID string
	subs        map[string]remoteSub
	cancelled   []string
}

func (f *fakeStripe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
	sub, ok := f.subs[id]
	if !ok {
		http.Error(w, `{"error":{"message":"no such subscription"}}`, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodDelete {
		f.cancelled = append(f.cancelled, id)
		sub.status = "canceled"
		f.subs[id] = sub
	}
	body := map[string]any{
		"id":                   id,
		"object":               "subscription",
		"status":               sub.status,
		"customer":             "cus_1",
		"cancel_at_period_end": sub.cancelAt,
		"metadata":             map[string]string{"workspace_id": f.workspaceID},
		"items": map[string]any{"data": []map[string]any{{
			"quantity":           sub.seats,
			"current_period_end": time.Now().Add(24 * time.Hour).Unix(),
		}}},
	}
	if sub.endedAt != 0 {
		body["ended_at"] = sub.endedAt
	}
	_ = json.NewEncoder(w).Encode(body)
}

func newSync(t *testing.T) *fakeStripe {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	require.NoError(t, err)

	fake := &fakeStripe{conn: conn, subs: map[string]remoteSub{}, workspaceID: uuid.NewV7().String()}
	pinned := actor.WithWorkspace(t.Context(), actor.Workspace{ID: fake.workspaceID})
	require.NoError(t, conn.TenantTx(pinned, func(q *db.Queries) error {
		if _, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{
			ID:   fake.workspaceID,
			Slug: "b" + strings.ReplaceAll(uuid.New().String(), "-", ""), Name: "billing",
			Settings: &nokkuv1.WorkspaceSettings{},
		}); err != nil {
			return err
		}
		return q.InitSubscription(t.Context())
	}))

	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	// billing.New takes the SDK's default backend, so that one is the fake.
	stripe.SetBackend(stripe.APIBackend, stripe.GetBackendWithConfig(stripe.APIBackend, &stripe.BackendConfig{
		URL:               new(srv.URL),
		MaxNetworkRetries: new(int64(0)),
	}))
	t.Cleanup(func() { stripe.SetBackend(stripe.APIBackend, nil) })
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_x")
	t.Setenv("STRIPE_WEBHOOK_SECRET", webhookSecret)
	t.Setenv("STRIPE_PRO_PRICE_ID", "price_x")
	fake.billing, err = billing.New(t.Context(), conn, "https://nokku.test", true)
	require.NoError(t, err)
	return fake
}

// event delivers the webhook Stripe sends when the subscription changed and
// returns the status Stripe gets back. Anything but 200 makes it retry.
func (f *fakeStripe) event(t *testing.T, subscriptionID string) int {
	t.Helper()
	payload := fmt.Appendf(
		nil,
		`{"id":"evt_1","object":"event","api_version":%q,"type":"customer.subscription.updated","data":{"object":{"id":%q}}}`,
		stripe.APIVersion,
		subscriptionID,
	)
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: webhookSecret})
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(payload))
	r.Header.Set("Stripe-Signature", signed.Header)
	w := httptest.NewRecorder()
	f.billing.WebhookHandler().ServeHTTP(w, r)
	return w.Code
}

// row is the subscription the workspace has in the database.
func (f *fakeStripe) row(t *testing.T) *db.WorkspaceSubscription {
	t.Helper()
	row, err := f.conn.Sys().GetSubscription(t.Context(), f.workspaceID)
	require.NoError(t, err)
	return row
}

func TestSync_MirrorsSeatsAndStatus(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 7}

	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	row := fake.row(t)
	assert.Equal(t, string(entitlement.StatusActive), row.Status)
	assert.EqualValues(t, 7, row.Seats, "the paid quantity is the seat cap")
	assert.Nil(t, row.EndedAt)
}

func TestSync_EndedSubscriptionKeepsPlanForTheHold(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	ended := time.Now().Add(-time.Hour).Unix()
	fake.subs["sub_a"] = remoteSub{status: "canceled", seats: 5, endedAt: ended}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	row := fake.row(t)
	assert.Equal(t, string(entitlement.StatusInactive), row.Status)
	assert.Equal(t, entitlement.PlanPro, row.Plan, "the retention hold reads the ended plan")
	require.NotNil(t, row.EndedAt)
	assert.Equal(t, ended, row.EndedAt.Unix())
}

func TestSync_LateEventForOldSubscriptionKeepsTheLiveOne(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_old"] = remoteSub{status: "canceled", endedAt: time.Now().Unix()}
	fake.subs["sub_live"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_live"))

	require.Equal(t, http.StatusOK, fake.event(t, "sub_old"))

	row := fake.row(t)
	assert.Equal(t, "sub_live", row.SubscriptionID)
	assert.Equal(t, string(entitlement.StatusActive), row.Status, "a paying workspace must not be downgraded")
}

func TestSync_DuplicateSubscriptionIsCancelled(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_keep"] = remoteSub{status: "active", seats: 5}
	fake.subs["sub_dup"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_keep"))

	require.Equal(t, http.StatusOK, fake.event(t, "sub_dup"))

	assert.Equal(t, []string{"sub_dup"}, fake.cancelled)
	row := fake.row(t)
	assert.Equal(t, "sub_keep", row.SubscriptionID)
}

func TestSync_NewSubscriptionReplacesOneThatEndedUnnoticed(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_old"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_old"))

	// The old one ended at Stripe, but that event has not arrived yet.
	fake.subs["sub_old"] = remoteSub{status: "canceled", endedAt: time.Now().Unix()}
	fake.subs["sub_new"] = remoteSub{status: "active", seats: 9}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_new"))

	assert.Empty(t, fake.cancelled, "a paid subscription must not be cancelled over a stale row")
	row := fake.row(t)
	assert.Equal(t, "sub_new", row.SubscriptionID)
	assert.EqualValues(t, 9, row.Seats)
}

func TestSync_DeletedWorkspaceIsNotAnError(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "canceled", endedAt: time.Now().Unix()}
	fake.workspaceID = uuid.New().String()

	assert.Equal(t, http.StatusOK, fake.event(t, "sub_a"), "a 500 here would make Stripe retry forever")
}

func TestCancel_FreeWorkspaceHasNothingToCancel(t *testing.T) {
	fake := newSync(t)
	assert.NoError(t, fake.billing.Cancel(t.Context(), fake.workspaceID, true, ""),
		"deleting a free workspace calls this and must not fail")
}
