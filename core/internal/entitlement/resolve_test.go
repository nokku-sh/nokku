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
		{"the row a workspace starts with", &db.WorkspaceSubscription{}, nil, PlanCommunity, PlanCommunity},
		{"no row", nil, pgx.ErrNoRows, PlanCommunity, PlanCommunity},
		{
			"ended ten days ago holds its data limits",
			&db.WorkspaceSubscription{Plan: PlanPro, Status: "canceled", EndedAt: daysAgo(10)},
			nil, PlanCommunity, PlanPro,
		},
		{
			"the hold ends after 30 days",
			&db.WorkspaceSubscription{Plan: PlanPro, Status: "canceled", EndedAt: daysAgo(holdDays + 1)},
			nil, PlanCommunity, PlanCommunity,
		},
		{
			// An abandoned checkout leaves a row that never ended.
			"never paid gets no hold",
			&db.WorkspaceSubscription{Plan: PlanPro, Status: "incomplete_expired"},
			nil, PlanCommunity, PlanCommunity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, keep, err := fromSubscription(tt.sub, tt.err)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPlan, plan.Name)
			assert.Equal(t, tt.wantKeep, keep.Name)
		})
	}
}

func TestFromSubscription_PaidQuantityIsTheSeatCap(t *testing.T) {
	plan, _, err := fromSubscription(&db.WorkspaceSubscription{Plan: PlanPro, Status: "active", Seats: 7}, nil)
	require.NoError(t, err)
	assert.EqualValues(t, 7, plan.SeatCap)
}

func TestFromSubscription_FailsClosed(t *testing.T) {
	// The row GetSubscription hands back next to an error is not to be trusted.
	paid := &db.WorkspaceSubscription{Plan: PlanEnterprise, Status: "active"}
	plan, keep, err := fromSubscription(paid, errors.New("connection refused"))

	require.Error(t, err, "the purge jobs skip on this error, an outage must never delete data")
	assert.Equal(t, PlanCommunity, plan.Name, "an outage must never hand out paid features")
	assert.Equal(t, PlanCommunity, keep.Name)
	assert.False(t, plan.Has(FeatureSCIM) || plan.Has(FeatureAuditExport) || plan.Has(FeatureEnforceSSO))
}

func TestActive(t *testing.T) {
	for _, status := range []string{"active", "trialing", "past_due"} {
		assert.True(t, Active(status), status)
	}
	for _, status := range []string{
		"canceled", "unpaid", "paused", "incomplete", "incomplete_expired", "inactive", "bogus", "",
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
			plan, keep := fromLicense(tt.claims)
			assert.Equal(t, tt.wantPlan, plan.Name)
			assert.Equal(t, tt.wantKeep, keep.Name)
		})
	}
}

func TestSelfHosted_ExpiredLicenseKeepsItsDataLimits(t *testing.T) {
	ctx := t.Context()
	sut := selfHosted(t, issue(t, PlanEnterprise, -24*time.Hour))

	assert.Equal(t, PlanCommunity, sut.Resolve(ctx, "ws1").Name, "licensed features end with the key")
	days, err := sut.RetentionDays(ctx, "ws1")
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
	assert.NoError(t, licensed.CanInvite(ctx, "ws1", 5000), "a licensed server counts no seats")
}
