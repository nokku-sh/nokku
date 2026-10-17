package entitlement

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/inkan/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// testSigner signs the keys of the tests, testPublicKey verifies them.
var testSigner, testPublicKey = func() (ed25519.PrivateKey, string) {
	privB64, pubHex, err := license.GenerateKey()
	if err != nil {
		panic(err)
	}
	priv, err := license.ParsePrivateKey(privB64)
	if err != nil {
		panic(err)
	}
	return priv, pubHex
}()

// issue signs a key of that plan. A validFor of 0 never expires.
func issue(t *testing.T, plan string, validFor time.Duration) string {
	t.Helper()
	claims := license.Claims{Plan: plan}
	if validFor != 0 {
		claims.ExpiresAt = time.Now().Add(validFor).Unix()
	}
	key, err := license.Issue(licenseApp, claims, testSigner)
	require.NoError(t, err)
	return key
}

// issueSeats signs a key that carries a seat count.
func issueSeats(t *testing.T, plan string, validFor time.Duration, seats string) string {
	t.Helper()
	claims := license.Claims{
		Plan:      plan,
		ExpiresAt: time.Now().Add(validFor).Unix(),
		Meta:      map[string]string{"seats": seats},
	}
	key, err := license.Issue(licenseApp, claims, testSigner)
	require.NoError(t, err)
	return key
}

// selfHosted is a server without a database, a self-hosted plan lookup never reads one.
func selfHosted(t *testing.T, keys ...string) *Service {
	t.Helper()
	s := newService(nil, testPublicKey, false)
	for _, key := range keys {
		require.NoError(t, s.takeLicense(key))
	}
	return s
}

func daysAgo(days int) *time.Time {
	return new(time.Now().AddDate(0, 0, -days))
}

func TestFromSubscription(t *testing.T) {
	tests := []struct {
		name     string
		sub      *db.WorkspaceSubscription
		err      error
		wantPlan string
		wantKeep string
	}{
		{"active", &db.WorkspaceSubscription{Plan: PlanPro, Status: "active"}, nil, PlanPro, PlanPro},
		{
			"trialing",
			&db.WorkspaceSubscription{Plan: PlanEnterprise, Status: "trialing"},
			nil,
			PlanEnterprise,
			PlanEnterprise,
		},
		{
			"past due is a grace period",
			&db.WorkspaceSubscription{Plan: PlanPro, Status: "past_due"},
			nil,
			PlanPro,
			PlanPro,
		},
		{"an empty row", &db.WorkspaceSubscription{}, nil, PlanInactive, PlanInactive},
		{"no row", nil, pgx.ErrNoRows, PlanInactive, PlanInactive},
		{
			"ended ten days ago holds its data limits",
			&db.WorkspaceSubscription{Plan: PlanPro, Status: "canceled", EndedAt: daysAgo(10)},
			nil, PlanInactive, PlanPro,
		},
		{
			"the hold ends after 30 days",
			&db.WorkspaceSubscription{Plan: PlanPro, Status: "canceled", EndedAt: daysAgo(holdDays + 1)},
			nil, PlanInactive, PlanInactive,
		},
		{
			// An abandoned checkout leaves a row that never ended.
			"never paid gets no hold",
			&db.WorkspaceSubscription{Plan: PlanPro, Status: "incomplete_expired"},
			nil, PlanInactive, PlanInactive,
		},
		{
			"a running trial",
			&db.WorkspaceSubscription{
				Source:           SourceTrial,
				Plan:             PlanPro,
				Status:           "trial",
				CurrentPeriodEnd: daysAgo(-3),
			},
			nil,
			PlanPro,
			PlanPro,
		},
		{
			"a trial that ended holds its data limits",
			&db.WorkspaceSubscription{
				Source:           SourceTrial,
				Plan:             PlanPro,
				Status:           "trial",
				CurrentPeriodEnd: daysAgo(2),
			},
			nil,
			PlanInactive,
			PlanPro,
		},
		{
			"the hold of a trial ends after 30 days",
			&db.WorkspaceSubscription{
				Source: SourceTrial, Plan: PlanPro, Status: "trial", CurrentPeriodEnd: daysAgo(holdDays + 1),
			},
			nil, PlanInactive, PlanInactive,
		},
		{
			"a trial without an end never runs",
			&db.WorkspaceSubscription{Source: SourceTrial, Plan: PlanPro, Status: "trial"},
			nil, PlanInactive, PlanInactive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, err := fromSubscription(tt.sub, tt.err)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPlan, st.Plan.Name)
			assert.Equal(t, tt.wantKeep, st.Keep.Name)
			assert.Equal(t, tt.wantPlan != tt.wantKeep, st.HeldUntil != nil, "a hold has an end")
		})
	}
}

func TestFromSubscription_PaidQuantityIsTheSeatCap(t *testing.T) {
	st, err := fromSubscription(&db.WorkspaceSubscription{Plan: PlanPro, Status: "active", Seats: 7}, nil)
	require.NoError(t, err)
	assert.EqualValues(t, 7, st.Plan.SeatCap)
}

func TestFromSubscription_FailsClosed(t *testing.T) {
	// The row GetSubscription hands back next to an error is not to be trusted.
	paid := &db.WorkspaceSubscription{Plan: PlanEnterprise, Status: "active"}
	st, err := fromSubscription(paid, errors.New("connection refused"))
	plan := st.Plan

	require.Error(t, err, "the purge jobs skip on this error, an outage must never delete data")
	assert.Equal(t, PlanCommunity, plan.Name, "an outage must never hand out paid features, nor stop signing")
	assert.Equal(t, PlanCommunity, st.Keep.Name)
	assert.False(t, plan.Has(FeatureSCIM) || plan.Has(FeatureAuditExport) || plan.Has(FeatureEnforceSSO))
}

func TestActive(t *testing.T) {
	for _, status := range []string{"active", "trialing", "past_due"} {
		assert.True(t, Active(status), status)
	}
	for _, status := range []string{
		"canceled", "unpaid", "paused", "incomplete", "incomplete_expired", "inactive", SourceTrial, "bogus", "",
	} {
		assert.False(t, Active(status), "%q must not pay for a plan", status)
	}
}

func TestFromLicense(t *testing.T) {
	tests := []struct {
		name     string
		claims   *license.Claims
		wantPlan string
		wantKeep string
	}{
		{"no key", nil, PlanCommunity, PlanCommunity},
		{"a key that never expires", &license.Claims{Plan: PlanEnterprise}, PlanEnterprise, PlanEnterprise},
		{
			"a valid key",
			&license.Claims{Plan: PlanEnterprise, ExpiresAt: time.Now().Add(time.Hour).Unix()},
			PlanEnterprise, PlanEnterprise,
		},
		{"an unknown plan", &license.Claims{Plan: "ultimate"}, PlanCommunity, PlanCommunity},
		{
			"expired yesterday holds its data limits",
			&license.Claims{Plan: PlanEnterprise, ExpiresAt: daysAgo(1).Unix()},
			PlanCommunity, PlanEnterprise,
		},
		{
			"the hold ends after 30 days",
			&license.Claims{Plan: PlanEnterprise, ExpiresAt: daysAgo(holdDays + 1).Unix()},
			PlanCommunity, PlanCommunity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := fromLicense(tt.claims)
			assert.Equal(t, tt.wantPlan, st.Plan.Name)
			assert.Equal(t, tt.wantKeep, st.Keep.Name)
		})
	}
}

func TestSelfHosted_ExpiredLicenseKeepsItsDataLimits(t *testing.T) {
	ctx := t.Context()
	sut := selfHosted(t, issue(t, PlanEnterprise, -24*time.Hour))

	assert.Equal(t, PlanCommunity, sut.Resolve(ctx, "ws1").Name, "licensed features end with the key")
	days, err := sut.AuditRetentionDays(ctx, "ws1")
	require.NoError(t, err)
	assert.EqualValues(t, 365, days, "an expired license must not purge data right away")
}

// The caps protect SaaS infrastructure only, on self-hosted the disk and the hosts are the customer's own.
func TestSelfHosted_IsNeverCapped(t *testing.T) {
	ctx := t.Context()
	for name, sut := range map[string]*Service{
		"community": selfHosted(t),
		"licensed":  selfHosted(t, issue(t, PlanEnterprise, time.Hour)),
	} {
		plan := sut.Resolve(ctx, "ws1")
		assert.Equal(t, unlimited, plan.ResourceCap, name)
		assert.Equal(t, unlimited, plan.RecordingStorageBytes, name)
		require.NoError(t, sut.CheckResources(ctx, "ws1"), name)

		capBytes, err := sut.RecordingStorageBytes(ctx, "ws1")
		require.NoError(t, err)
		assert.Equal(t, unlimited, capBytes, "%s: the purge jobs must see no storage cap either", name)
	}
}

func TestCanInvite(t *testing.T) {
	ctx := t.Context()
	community := selfHosted(t)
	require.NoError(t, community.CanInvite(ctx, "ws1", 4))
	require.ErrorContains(t, community.CanInvite(ctx, "ws1", 5), "your plan includes 5 members")

	licensed := selfHosted(t, issue(t, PlanEnterprise, time.Hour))
	require.NoError(t, licensed.CanInvite(ctx, "ws1", 5000), "an Enterprise key without seats counts none")

	pro := selfHosted(t, issueSeats(t, PlanPro, time.Hour, "12"))
	require.NoError(t, pro.CanInvite(ctx, "ws1", 11))
	require.ErrorContains(t, pro.CanInvite(ctx, "ws1", 12), "all 12 seats are in use")
}

func TestFromLicense_SeatsAreTheCap(t *testing.T) {
	st := fromLicense(&license.Claims{Plan: PlanPro, Meta: map[string]string{"seats": "20"}})
	assert.Equal(t, PlanPro, st.Plan.Name)
	assert.EqualValues(t, 20, st.Plan.SeatCap)

	expired := &license.Claims{Plan: PlanPro, ExpiresAt: daysAgo(1).Unix(), Meta: map[string]string{"seats": "20"}}
	assert.EqualValues(t, 5, fromLicense(expired).Plan.SeatCap, "an expired key drops to the Community cap")
}

func TestStatus_SelfHostedHold(t *testing.T) {
	ctx := t.Context()
	st, err := selfHosted(t).Status(ctx, "ws1")
	require.NoError(t, err)
	assert.Nil(t, st.HeldUntil, "no key, no hold")

	st, _ = selfHosted(t, issue(t, PlanEnterprise, time.Hour)).Status(ctx, "ws1")
	assert.Nil(t, st.HeldUntil, "a valid key holds nothing, it is in force")

	st, _ = selfHosted(t, issue(t, PlanEnterprise, -24*time.Hour)).Status(ctx, "ws1")
	assert.Equal(t, PlanCommunity, st.Plan.Name)
	assert.Equal(t, PlanEnterprise, st.Keep.Name)
	require.NotNil(t, st.HeldUntil)
	assert.WithinDuration(t, time.Now().Add((holdDays-1)*24*time.Hour), *st.HeldUntil, time.Minute)
}
