package billing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	stripe "github.com/stripe/stripe-go/v86"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	"github.com/nokku-sh/nokku/internal/testdb"
)

func TestMain(m *testing.M) {
	testdb.Setup("billing")
	os.Exit(m.Run())
}

type remoteSub struct {
	status   string
	seats    int64
	endedAt  int64
	cancelAt bool
}

// fakeStripe serves the two subscription calls sync makes.
type fakeStripe struct {
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

func newSync(t *testing.T) (*Stripe, *fakeStripe) {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	if err != nil {
		t.Skipf("no test database: %v", err)
	}

	fake := &fakeStripe{subs: map[string]remoteSub{}}
	require.NoError(t, conn.WithTx(t.Context(), func(q *db.Queries) error {
		u, err := q.CreateUser(t.Context(), &db.CreateUserParams{
			Email: uuid.New().String() + "@billing.test", Name: "owner",
		})
		if err != nil {
			return err
		}
		ws, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{Name: "billing", CreatedBy: u.ID})
		fake.workspaceID = ws.ID
		return err
	}))

	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	client := stripe.NewClient("sk_test_x", stripe.WithBackends(
		stripe.NewBackendsWithConfig(&stripe.BackendConfig{
			URL:               new(srv.URL),
			MaxNetworkRetries: new(int64(0)),
		}),
	))
	return &Stripe{client: client, db: conn}, fake
}

func TestSync_MirrorsSeatsAndStatus(t *testing.T) {
	s, fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 7}

	require.NoError(t, s.sync(t.Context(), "sub_a"))

	row, err := s.subscription(t.Context(), fake.workspaceID)
	require.NoError(t, err)
	assert.Equal(t, string(entitlement.StatusActive), row.Status)
	assert.EqualValues(t, 7, row.Seats, "the paid quantity is the seat cap")
	assert.Nil(t, row.EndedAt)
}

func TestSync_EndedSubscriptionKeepsPlanForTheHold(t *testing.T) {
	s, fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 5}
	require.NoError(t, s.sync(t.Context(), "sub_a"))

	ended := time.Now().Add(-time.Hour).Unix()
	fake.subs["sub_a"] = remoteSub{status: "canceled", seats: 5, endedAt: ended}
	require.NoError(t, s.sync(t.Context(), "sub_a"))

	row, err := s.subscription(t.Context(), fake.workspaceID)
	require.NoError(t, err)
	assert.Equal(t, string(entitlement.StatusInactive), row.Status)
	assert.Equal(t, entitlement.PlanPro, row.Plan, "the retention hold reads the ended plan")
	require.NotNil(t, row.EndedAt)
	assert.Equal(t, ended, row.EndedAt.Unix())
}

func TestSync_LateEventForOldSubscriptionKeepsTheLiveOne(t *testing.T) {
	s, fake := newSync(t)
	fake.subs["sub_old"] = remoteSub{status: "canceled", endedAt: time.Now().Unix()}
	fake.subs["sub_live"] = remoteSub{status: "active", seats: 5}
	require.NoError(t, s.sync(t.Context(), "sub_live"))

	require.NoError(t, s.sync(t.Context(), "sub_old"))

	row, err := s.subscription(t.Context(), fake.workspaceID)
	require.NoError(t, err)
	assert.Equal(t, "sub_live", row.SubscriptionID)
	assert.Equal(t, string(entitlement.StatusActive), row.Status, "a paying workspace must not be downgraded")
}

func TestSync_DuplicateSubscriptionIsCancelled(t *testing.T) {
	s, fake := newSync(t)
	fake.subs["sub_keep"] = remoteSub{status: "active", seats: 5}
	fake.subs["sub_dup"] = remoteSub{status: "active", seats: 5}
	require.NoError(t, s.sync(t.Context(), "sub_keep"))

	require.NoError(t, s.sync(t.Context(), "sub_dup"))

	assert.Equal(t, []string{"sub_dup"}, fake.cancelled)
	row, err := s.subscription(t.Context(), fake.workspaceID)
	require.NoError(t, err)
	assert.Equal(t, "sub_keep", row.SubscriptionID)
}

func TestSync_NewSubscriptionReplacesOneThatEndedUnnoticed(t *testing.T) {
	s, fake := newSync(t)
	fake.subs["sub_old"] = remoteSub{status: "active", seats: 5}
	require.NoError(t, s.sync(t.Context(), "sub_old"))

	// The old one ended at Stripe, but that event has not arrived yet.
	fake.subs["sub_old"] = remoteSub{status: "canceled", endedAt: time.Now().Unix()}
	fake.subs["sub_new"] = remoteSub{status: "active", seats: 9}
	require.NoError(t, s.sync(t.Context(), "sub_new"))

	assert.Empty(t, fake.cancelled, "a paid subscription must not be cancelled over a stale row")
	row, err := s.subscription(t.Context(), fake.workspaceID)
	require.NoError(t, err)
	assert.Equal(t, "sub_new", row.SubscriptionID)
	assert.EqualValues(t, 9, row.Seats)
}

func TestSync_DeletedWorkspaceIsNotAnError(t *testing.T) {
	s, fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "canceled", endedAt: time.Now().Unix()}
	fake.workspaceID = uuid.New().String()

	assert.NoError(t, s.sync(t.Context(), "sub_a"), "a 500 here would make Stripe retry forever")
}

func TestCancel_FreeWorkspaceHasNothingToCancel(t *testing.T) {
	s, fake := newSync(t)
	assert.NoError(t, s.cancel(t.Context(), fake.workspaceID, true, ""),
		"deleting a free workspace calls this and must not fail")
}
