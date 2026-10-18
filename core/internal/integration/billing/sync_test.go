//go:build integration

package billing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	stripe "github.com/stripe/stripe-go/v86"
	"github.com/stripe/stripe-go/v86/webhook"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/billing"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
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

// fakeStripe is the hosted service on a Stripe that serves the two subscription calls a sync makes.
type fakeStripe struct {
	billing *billing.Stripe
	conn    *db.Connection

	mu          sync.Mutex
	workspaceID string
	subs        map[string]remoteSub
	cancelled   []string
	raised      []string
	checkouts   []url.Values
}

func (f *fakeStripe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/v1/checkout/sessions" {
		_ = r.ParseForm()
		f.checkouts = append(f.checkouts, r.PostForm)
		_, _ = w.Write([]byte(`{"id":"cs_1","object":"checkout.session","url":"https://checkout.test/cs_1"}`))
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
	sub, ok := f.subs[id]
	if !ok {
		http.Error(w, `{"error":{"message":"no such subscription"}}`, http.StatusNotFound)
		return
	}
	_ = r.ParseForm()
	switch {
	case r.Method == http.MethodDelete:
		f.cancelled = append(f.cancelled, id)
		sub.status = "canceled"
		f.subs[id] = sub
	case r.PostForm.Has("items[0][quantity]"):
		f.raised = append(f.raised, r.PostForm.Get("items[0][quantity]"))
		sub.seats, _ = strconv.ParseInt(r.PostForm.Get("items[0][quantity]"), 10, 64)
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
			"id":                 "si_1",
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
		return q.StartTrial(t.Context(), &db.StartTrialParams{
			Plan: entitlement.PlanPro,
			Days: entitlement.TrialDays,
		})
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
	t.Setenv("STRIPE_PRO_MONTHLY_PRICE_ID", "price_m")
	t.Setenv("STRIPE_PRO_YEARLY_PRICE_ID", "price_y")
	fake.billing, err = billing.New(t.Context(), conn, true)
	require.NoError(t, err)
	return fake
}

// event delivers the webhook and returns the status Stripe gets back. Anything but 200 makes it retry.
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

func (f *fakeStripe) row(t *testing.T) *db.WorkspaceSubscription {
	t.Helper()
	row, err := f.conn.Sys().GetSubscription(t.Context(), f.workspaceID)
	require.NoError(t, err)
	return row
}

func (f *fakeStripe) addMembers(t *testing.T, n int) {
	t.Helper()
	pinned := actor.WithWorkspace(t.Context(), actor.Workspace{ID: f.workspaceID})
	require.NoError(t, f.conn.TenantTx(pinned, func(q *db.Queries) error {
		for i := range n {
			if _, err := q.CreateUserWithID(pinned, &db.CreateUserWithIDParams{
				ID:    uuid.NewV7().String(),
				Email: fmt.Sprintf("member-%d@example.com", i),
				Name:  fmt.Sprintf("Member %d", i),
				Role:  nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
			}); err != nil {
				return err
			}
		}
		return nil
	}))
}

// plans is the plan lookup of the hosted service on the same database.
func (f *fakeStripe) plans(t *testing.T) *entitlement.Service {
	t.Helper()
	ent, err := entitlement.New(t.Context(), f.conn, "", true)
	require.NoError(t, err)
	return ent
}

func TestSync_MirrorsSeatsAndStatus(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 7}

	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	row := fake.row(t)
	assert.Equal(t, "active", row.Status)
	assert.EqualValues(t, 7, row.Seats, "the paid quantity is the seat cap")
	assert.Nil(t, row.EndedAt)
}

// From the webhook to what the workspace may do.
func TestSync_PaidSubscriptionIsThePlan(t *testing.T) {
	ctx := t.Context()
	fake := newSync(t)
	ent := fake.plans(t)
	assert.Equal(t, entitlement.PlanPro, ent.Resolve(ctx, fake.workspaceID).Name, "a new workspace is on a trial")

	fake.subs["sub_a"] = remoteSub{status: "active", seats: 7}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	plan := ent.Resolve(ctx, fake.workspaceID)
	assert.Equal(t, entitlement.PlanPro, plan.Name)
	assert.EqualValues(t, 7, plan.SeatCap)
	require.NoError(t, ent.CanInvite(ctx, fake.workspaceID, 6))
	require.ErrorContains(t, ent.CanInvite(ctx, fake.workspaceID, 7), "all 7 seats are in use",
		"the eighth member needs an eighth seat")

	fake.subs["sub_a"] = remoteSub{status: "past_due", seats: 7}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))
	assert.Equal(t, entitlement.PlanPro, ent.Resolve(ctx, fake.workspaceID).Name, "past due is a grace period")

	fake.subs["sub_a"] = remoteSub{status: "unpaid", seats: 7}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))
	assert.Equal(t, entitlement.PlanInactive, ent.Resolve(ctx, fake.workspaceID).Name, "hosted has no free plan")
}

func TestSync_EndedSubscriptionKeepsPlanForTheHold(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	ended := time.Now().Add(-time.Hour).Unix()
	fake.subs["sub_a"] = remoteSub{status: "canceled", seats: 5, endedAt: ended}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	row := fake.row(t)
	assert.Equal(t, "canceled", row.Status)
	assert.Equal(t, entitlement.PlanPro, row.Plan, "the retention hold reads the ended plan")
	require.NotNil(t, row.EndedAt)
	assert.Equal(t, ended, row.EndedAt.Unix())

	ent := fake.plans(t)
	assert.Equal(t, entitlement.PlanInactive, ent.Resolve(t.Context(), fake.workspaceID).Name,
		"paid features end with the plan")
	days, err := ent.AuditRetentionDays(t.Context(), fake.workspaceID)
	require.NoError(t, err)
	assert.EqualValues(t, 90, days, "retention must hold for 30 days after the plan ended")
	capBytes, err := ent.RecordingStorageBytes(t.Context(), fake.workspaceID)
	require.NoError(t, err)
	assert.EqualValues(t, 50<<30, capBytes, "the storage cap must hold too, or eviction deletes recordings")

	st, err := ent.Status(t.Context(), fake.workspaceID)
	require.NoError(t, err)
	assert.Equal(t, entitlement.PlanPro, st.Keep.Name, "billing shows what the hold keeps")
	require.NotNil(t, st.HeldUntil)
	assert.Equal(t, entitlement.HoldEnd(time.Unix(ended, 0)), *st.HeldUntil)
}

func TestSync_LateEventForOldSubscriptionKeepsTheLiveOne(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_old"] = remoteSub{status: "canceled", endedAt: time.Now().Unix()}
	fake.subs["sub_live"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_live"))

	require.Equal(t, http.StatusOK, fake.event(t, "sub_old"))

	row := fake.row(t)
	assert.Equal(t, "sub_live", row.SubscriptionID)
	assert.Equal(t, "active", row.Status, "a paying workspace must not be downgraded")
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

func TestSync_RaisesSeatsToTheMemberCount(t *testing.T) {
	fake := newSync(t)
	fake.addMembers(t, 8)
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 5}

	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	assert.Equal(t, []string{"8"}, fake.raised, "eight members need eight seats")
	assert.EqualValues(t, 8, fake.row(t).Seats)

	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))
	assert.Len(t, fake.raised, 1, "the webhook of the raise must not raise again")
}

func TestSync_DoesNotRaiseSeatsOfAPastDueSubscription(t *testing.T) {
	fake := newSync(t)
	fake.addMembers(t, 8)
	fake.subs["sub_a"] = remoteSub{status: "past_due", seats: 5}

	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	assert.Empty(t, fake.raised, "a customer whose payment failed must not be charged more")
	assert.EqualValues(t, 5, fake.row(t).Seats)
}

func TestCheckout_YearlyUsesTheYearlyPrice(t *testing.T) {
	fake := newSync(t)

	_, err := fake.billing.Checkout(t.Context(), actor.Workspace{ID: fake.workspaceID}, "owner@example.com", true)
	require.NoError(t, err)
	assert.Equal(t, "price_y", fake.checkouts[0].Get("line_items[0][price]"))
}

func TestCheckout_ReturnsToTheWorkspaceHost(t *testing.T) {
	fake := newSync(t)
	ws := actor.Workspace{ID: fake.workspaceID, BaseURL: "https://acme.nokku.test"}

	_, err := fake.billing.Checkout(t.Context(), ws, "owner@example.com", false)
	require.NoError(t, err)
	assert.Equal(t, "https://acme.nokku.test/settings/billing", fake.checkouts[0].Get("success_url"),
		"the hosted root host has no workspace to land in")
	assert.Equal(t, "https://acme.nokku.test/settings/billing", fake.checkouts[0].Get("cancel_url"))
}

func TestCheckout_NewWorkspaceGetsItsCustomerFromCheckout(t *testing.T) {
	ctx := t.Context()
	fake := newSync(t)

	link, err := fake.billing.Checkout(ctx, actor.Workspace{ID: fake.workspaceID}, "owner@example.com", false)
	require.NoError(t, err)
	assert.Equal(t, "https://checkout.test/cs_1", link)
	first := fake.checkouts[0]
	assert.Equal(t, "owner@example.com", first.Get("customer_email"))
	assert.Empty(t, first.Get("customer"))
	assert.Equal(t, fake.workspaceID, first.Get("subscription_data[metadata][workspace_id]"),
		"sync finds the workspace through this")
	assert.Equal(t, "3", first.Get("line_items[0][quantity]"), "three seats is the floor")
	assert.Equal(t, "price_m", first.Get("line_items[0][price]"))
	assert.Equal(t, "true", first.Get("managed_payments[enabled]"), "Stripe is the merchant of record and collects tax")

	fake.subs["sub_a"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))
	_, err = fake.billing.Checkout(ctx, actor.Workspace{ID: fake.workspaceID}, "owner@example.com", false)
	require.ErrorIs(t, err, billing.ErrActiveSubscription, "a paying workspace must not get a second subscription")

	fake.subs["sub_a"] = remoteSub{status: "canceled", seats: 5, endedAt: time.Now().Unix()}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))
	_, err = fake.billing.Checkout(ctx, actor.Workspace{ID: fake.workspaceID}, "owner@example.com", false)
	require.NoError(t, err)
	again := fake.checkouts[1]
	assert.Equal(t, "cus_1", again.Get("customer"), "a workspace that paid before keeps its customer")
	assert.Empty(t, again.Get("customer_email"), "Stripe takes one of the two")
}

func TestCancel_FreeWorkspaceHasNothingToCancel(t *testing.T) {
	fake := newSync(t)
	assert.NoError(t, fake.billing.Cancel(t.Context(), fake.workspaceID, true, ""),
		"deleting a free workspace calls this and must not fail")
}

// endTrial moves the trial end into the past, as if the days ran out.
func (f *fakeStripe) endTrial(t *testing.T, ago time.Duration) {
	t.Helper()
	require.NoError(t, f.conn.Sys().UpsertSubscription(t.Context(), &db.UpsertSubscriptionParams{
		WorkspaceID:      f.workspaceID,
		Source:           entitlement.SourceTrial,
		Plan:             entitlement.PlanPro,
		Status:           "trial",
		CurrentPeriodEnd: new(time.Now().Add(-ago)),
	}))
}

func TestTrial_EndedWorkspaceTakesNothingNew(t *testing.T) {
	ctx := t.Context()
	fake := newSync(t)
	ent := fake.plans(t)
	require.NoError(t, ent.CheckResources(ctx, fake.workspaceID))
	require.NoError(t, ent.CanInvite(ctx, fake.workspaceID, 20), "a trial has no seat cap")

	fake.endTrial(t, time.Hour)
	plan := ent.Resolve(ctx, fake.workspaceID)
	assert.Equal(t, entitlement.PlanInactive, plan.Name)
	for name, err := range map[string]error{
		"create": ent.CheckResources(ctx, fake.workspaceID),
		"invite": ent.CanInvite(ctx, fake.workspaceID, 1),
	} {
		require.Error(t, err, name)
		assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), name)
		require.ErrorContains(t, err, "no active plan", name)
	}

	days, err := ent.RecordingRetentionDays(ctx, fake.workspaceID)
	require.NoError(t, err)
	assert.EqualValues(t, 90, days, "the trial's data limits hold for 30 days")

	fake.endTrial(t, 31*24*time.Hour)
	days, err = ent.RecordingRetentionDays(ctx, fake.workspaceID)
	require.NoError(t, err)
	assert.EqualValues(t, 7, days)
}

func TestTrial_SubscriptionReplacesIt(t *testing.T) {
	fake := newSync(t)
	fake.subs["sub_a"] = remoteSub{status: "trialing", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	row := fake.row(t)
	assert.Equal(t, "stripe", row.Source, "the first checkout must replace the trial row")
	assert.Equal(t, "sub_a", row.SubscriptionID)
	assert.Equal(t, entitlement.PlanPro, fake.plans(t).Resolve(t.Context(), fake.workspaceID).Name)
}

func TestCheckout_KeepsTheRestOfTheTrial(t *testing.T) {
	fake := newSync(t)
	_, err := fake.billing.Checkout(t.Context(), actor.Workspace{ID: fake.workspaceID}, "owner@example.com", false)
	require.NoError(t, err)
	trialEnd, err := strconv.ParseInt(fake.checkouts[0].Get("subscription_data[trial_end]"), 10, 64)
	require.NoError(t, err, "paying early must not cut the trial short")
	assert.Equal(t, fake.row(t).CurrentPeriodEnd.Unix(), trialEnd)

	fake.endTrial(t, time.Hour)
	_, err = fake.billing.Checkout(t.Context(), actor.Workspace{ID: fake.workspaceID}, "owner@example.com", false)
	require.NoError(t, err)
	assert.Empty(t, fake.checkouts[1].Get("subscription_data[trial_end]"), "an ended trial is charged at once")
}

// Quotas fail open, features fail closed, and the purge jobs get an error instead of a shorter window.
func TestLookup_WhenTheDatabaseDoesNotAnswer(t *testing.T) {
	fake := newSync(t)
	ent := fake.plans(t)
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))

	down, cancel := context.WithCancel(t.Context())
	cancel()

	plan := ent.Resolve(down, fake.workspaceID)
	assert.Equal(t, entitlement.PlanCommunity, plan.Name, "an outage must never hand out paid features")
	assert.False(t, plan.Has(entitlement.FeatureAuditExport))
	assert.NotEqual(t, entitlement.PlanInactive, plan.Name, "an outage must never stop the workspace from signing")
	_, err := ent.AuditRetentionDays(down, fake.workspaceID)
	require.Error(t, err, "an outage must never shorten what is kept")
	assert.NoError(t, ent.CheckResources(down, fake.workspaceID), "a count that fails must not block a create")
}

// signViaGuard calls SignSSHCertificate through the guard, as the API serves it for the workspace.
func signViaGuard(t *testing.T, ent *entitlement.Service, workspaceID string) error {
	t.Helper()
	pin := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			return next(actor.WithWorkspace(ctx, actor.Workspace{ID: workspaceID}), req)
		}
	})
	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.CertificateServiceSignSSHCertificateProcedure, connect.NewUnaryHandler(
		nokkuv1connect.CertificateServiceSignSSHCertificateProcedure,
		func(context.Context, *connect.Request[nokkuv1.SignSSHCertificateRequest]) (
			*connect.Response[nokkuv1.SignSSHCertificateResponse], error,
		) {
			return connect.NewResponse(&nokkuv1.SignSSHCertificateResponse{}), nil
		},
		connect.WithInterceptors(pin, entitlement.NewGuardInterceptor(ent)),
	))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := connect.NewClient[nokkuv1.SignSSHCertificateRequest, nokkuv1.SignSSHCertificateResponse](
		srv.Client(), srv.URL+nokkuv1connect.CertificateServiceSignSSHCertificateProcedure,
	)
	_, err := client.CallUnary(t.Context(), connect.NewRequest(&nokkuv1.SignSSHCertificateRequest{}))
	return err
}

func TestGuard_EndedTrialSignsNothing(t *testing.T) {
	fake := newSync(t)
	ent := fake.plans(t)
	require.NoError(t, signViaGuard(t, ent, fake.workspaceID), "a trial signs")

	fake.endTrial(t, time.Hour)
	err := signViaGuard(t, ent, fake.workspaceID)
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	require.ErrorContains(t, err, "no active plan")

	fake.subs["sub_a"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))
	assert.NoError(t, signViaGuard(t, ent, fake.workspaceID), "subscribing signs again at once")
}

func TestTrial_RemindersAndExpiry(t *testing.T) {
	ctx := t.Context()
	fake := newSync(t)
	pinned := actor.WithWorkspace(ctx, actor.Workspace{ID: fake.workspaceID})
	require.NoError(t, fake.conn.TenantTx(pinned, func(q *db.Queries) error {
		_, err := q.CreateUserWithID(pinned, &db.CreateUserWithIDParams{
			ID: uuid.NewV7().String(), Email: "owner@example.com", Name: "Owner",
			Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER,
		})
		return err
	}))
	fake.addMembers(t, 2)
	sys := fake.conn.Sys()
	ending := func() []*db.ListTrialsEndingRow {
		rows, err := sys.ListTrialsEnding(ctx, 7)
		require.NoError(t, err)
		return slices.DeleteFunc(
			rows,
			func(r *db.ListTrialsEndingRow) bool { return r.WorkspaceID != fake.workspaceID },
		)
	}
	assert.Empty(t, ending(), "a fresh trial has 30 days left")

	fake.endTrial(t, -5*24*time.Hour)
	rows := ending()
	require.Len(t, rows, 1, "only the owner gets the reminder")
	assert.Equal(t, "owner@example.com", rows[0].OwnerEmail)
	assert.Zero(t, rows[0].TrialReminder)

	require.NoError(t, sys.SetTrialReminder(ctx, &db.SetTrialReminderParams{Days: 7, WorkspaceID: fake.workspaceID}))
	assert.EqualValues(t, 7, ending()[0].TrialReminder)

	lapsed := func() *db.ListLapsedWorkspacesRow {
		rows, err := sys.ListLapsedWorkspaces(ctx)
		require.NoError(t, err)
		for _, r := range rows {
			if r.WorkspaceSubscription.WorkspaceID == fake.workspaceID {
				return r
			}
		}
		return nil
	}
	assert.Nil(t, lapsed(), "a running trial is not lapsed")

	fake.endTrial(t, 24*time.Hour)
	row := lapsed()
	require.NotNil(t, row)
	require.NotNil(t, row.OwnerEmail)
	assert.Equal(t, "owner@example.com", *row.OwnerEmail)
	require.NotNil(t, entitlement.Ended(&row.WorkspaceSubscription), "the deletion countdown starts at the trial end")

	require.NoError(
		t,
		sys.SetDeletionWarning(ctx, &db.SetDeletionWarningParams{Days: 7, WorkspaceID: fake.workspaceID}),
	)
	row = lapsed()
	assert.EqualValues(t, 7, row.WorkspaceSubscription.DeletionWarning)
	require.NotNil(t, row.WorkspaceSubscription.DeletionWarnedAt)

	// Paying resets the countdown, a later lapse starts a new one.
	fake.subs["sub_a"] = remoteSub{status: "active", seats: 5}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))
	assert.Nil(t, lapsed(), "a paying workspace is not lapsed")

	fake.subs["sub_a"] = remoteSub{status: "canceled", seats: 5, endedAt: time.Now().AddDate(0, 0, -10).Unix()}
	require.Equal(t, http.StatusOK, fake.event(t, "sub_a"))
	row = lapsed()
	require.NotNil(t, row)
	assert.Zero(t, row.WorkspaceSubscription.DeletionWarning, "the warnings of an old countdown must not count")
	assert.Nil(t, row.WorkspaceSubscription.DeletionWarnedAt)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, -10), *entitlement.Ended(&row.WorkspaceSubscription), time.Minute)
}
