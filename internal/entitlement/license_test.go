package entitlement

import (
	"testing"
	"time"

	"github.com/mizuchilabs/kata/licx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuer swaps in a throwaway signing key and issues Enterprise keys.
func issuer(t *testing.T) func(validFor time.Duration) string {
	t.Helper()
	privB64, pubHex, err := licx.GenerateKey()
	require.NoError(t, err)
	require.NoError(t, licx.SetPublicKey(pubHex))
	t.Cleanup(func() { _ = licx.SetPublicKey("") })
	priv, err := licx.ParsePrivateKey(privB64)
	require.NoError(t, err)

	return func(validFor time.Duration) string {
		key, err := licx.Issue(licenseApp, licx.Claims{
			Plan:      PlanEnterprise,
			ExpiresAt: time.Now().Add(validFor).Unix(),
		}, priv)
		require.NoError(t, err)
		return key
	}
}

func daysAgo(days int) *time.Time {
	return new(time.Now().AddDate(0, 0, -days))
}

func TestHold_EndedSubscriptionKeepsItsDataLimits(t *testing.T) {
	ctx := t.Context()
	recent := NewService(
		&fakeDB{plan: PlanPro, status: StatusInactive, endedAt: daysAgo(10)}, nil, modeSaaS,
	)

	assert.Equal(t, PlanCommunity, recent.Resolve(ctx, "ws1").Name, "paid features end with the plan")
	days, err := recent.RetentionDays(ctx, "ws1")
	require.NoError(t, err)
	assert.EqualValues(t, 90, days, "retention must hold for 30 days after the plan ended")
	capBytes, err := recent.RecordingStorageBytes(ctx, "ws1")
	require.NoError(t, err)
	assert.EqualValues(t, 50<<30, capBytes, "the storage cap must hold too, or eviction deletes recordings")

	old := NewService(
		&fakeDB{plan: PlanPro, status: StatusInactive, endedAt: daysAgo(holdDays + 1)}, nil, modeSaaS,
	)
	days, err = old.RetentionDays(ctx, "ws1")
	require.NoError(t, err)
	assert.EqualValues(t, 7, days, "the hold ends after 30 days")
}

func TestHold_NeverPaidGetsNoHold(t *testing.T) {
	// An abandoned checkout leaves an inactive row without ended_at.
	sut := NewService(&fakeDB{plan: PlanPro, status: StatusInactive}, nil, modeSaaS)
	days, err := sut.RetentionDays(t.Context(), "ws1")
	require.NoError(t, err)
	assert.EqualValues(t, 7, days)
}

func TestHold_ExpiredLicenseKeepsItsDataLimits(t *testing.T) {
	ctx := t.Context()
	expired := func(days int) *licx.Claims {
		return &licx.Claims{Plan: PlanEnterprise, ExpiresAt: daysAgo(days).Unix()}
	}

	recent := NewService(&fakeDB{subErr: ErrNoSubscription}, expired(1), modeSelfHosted)
	assert.Equal(t, PlanCommunity, recent.Resolve(ctx, "ws1").Name)
	days, err := recent.RetentionDays(ctx, "ws1")
	require.NoError(t, err)
	assert.EqualValues(t, 365, days, "an expired license must not purge data right away")

	old := NewService(&fakeDB{subErr: ErrNoSubscription}, expired(holdDays+1), modeSelfHosted)
	days, err = old.RetentionDays(ctx, "ws1")
	require.NoError(t, err)
	assert.EqualValues(t, 7, days)
}

func TestSeats_PaidQuantityIsTheSeatCap(t *testing.T) {
	ctx := t.Context()
	sut := NewService(&fakeDB{plan: PlanPro, status: StatusActive, seats: 7}, nil, modeSaaS)

	assert.EqualValues(t, 7, sut.Resolve(ctx, "ws1").SeatCap)
	require.NoError(t, sut.CanInvite(ctx, "ws1", 6))
	assert.Error(t, sut.CanInvite(ctx, "ws1", 7), "the eighth member needs an eighth seat")
}

func TestActivateLicense(t *testing.T) {
	ctx := t.Context()
	issue := issuer(t)
	sut := NewService(&fakeDB{subErr: ErrNoSubscription}, nil, modeSelfHosted)

	require.ErrorIs(t, sut.ActivateLicense(ctx, "NOKKU-AAAAA-BBBBB"), ErrLicenseInvalid)
	require.ErrorIs(t, sut.ActivateLicense(ctx, issue(-time.Hour)), ErrLicenseExpired)
	assert.Nil(t, sut.License(), "a refused key must not become the license")

	require.NoError(t, sut.ActivateLicense(ctx, "  "+issue(365*24*time.Hour)+"\n"))
	assert.Equal(t, PlanEnterprise, sut.Resolve(ctx, "ws1").Name, "an activated key applies without a restart")

	require.ErrorIs(t, sut.ActivateLicense(ctx, issue(24*time.Hour)), ErrLicenseShorter,
		"an old key must not undo a renewal")

	hosted := NewService(&fakeDB{}, nil, modeSaaS)
	assert.ErrorIs(t, hosted.ActivateLicense(ctx, issue(time.Hour)), ErrNotSelfHosted)
}

func TestReloadLicense_LongestValidKeyWins(t *testing.T) {
	ctx := t.Context()
	issue := issuer(t)
	fromEnv, err := parseLicense(issue(24 * time.Hour))
	require.NoError(t, err)

	renewed := &fakeDB{licenseKey: issue(365 * 24 * time.Hour)}
	sut := NewService(renewed, fromEnv, modeSelfHosted)
	sut.reloadLicense(ctx)
	assert.Greater(t, sut.License().ExpiresAt, fromEnv.ExpiresAt, "the renewed key from the UI wins")

	stale := &fakeDB{licenseKey: issue(time.Hour)}
	sut = NewService(stale, fromEnv, modeSelfHosted)
	sut.reloadLicense(ctx)
	assert.Equal(t, fromEnv.ExpiresAt, sut.License().ExpiresAt, "a shorter stored key never replaces the env key")
}
