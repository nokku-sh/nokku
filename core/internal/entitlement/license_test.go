package entitlement

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const year = 365 * 24 * time.Hour

// Every refusal comes before the key is stored. The key that is taken is in internal/integration/api.
func TestActivateLicense_Refusals(t *testing.T) {
	ctx := t.Context()
	sut := selfHosted(t)

	require.ErrorIs(t, sut.ActivateLicense(ctx, "NOKKU-AAAAA-BBBBB"), ErrLicenseInvalid)
	require.ErrorIs(t, sut.ActivateLicense(ctx, issue(t, PlanPro, year)), ErrLicenseInvalid,
		"a Pro key must name its seats")
	require.ErrorIs(t, sut.ActivateLicense(ctx, issueSeats(t, PlanPro, year, "ten")), ErrLicenseInvalid)
	require.ErrorIs(t, sut.ActivateLicense(ctx, issueSeats(t, PlanPro, year, "0")), ErrLicenseInvalid)
	require.ErrorIs(t, sut.ActivateLicense(ctx, issue(t, "team", year)), ErrLicenseInvalid)
	require.ErrorIs(t, sut.ActivateLicense(ctx, issue(t, PlanEnterprise, -time.Hour)), ErrLicenseExpired)
	assert.Nil(t, sut.License(), "a refused key must not become the license")

	renewed := selfHosted(t, issue(t, PlanEnterprise, year))
	require.ErrorIs(t, renewed.ActivateLicense(ctx, issue(t, PlanEnterprise, 24*time.Hour)), ErrLicenseShorter,
		"an old key must not undo a renewal")

	hosted := newService(nil, testPublicKey, true)
	require.ErrorIs(t, hosted.ActivateLicense(ctx, issue(t, PlanEnterprise, year)), ErrNotSelfHosted)

	unbuilt := newService(nil, "", false)
	assert.ErrorIs(t, unbuilt.ActivateLicense(ctx, issue(t, PlanEnterprise, year)), ErrLicenseUnsupported)
}

// The environment is offered first, then the key activated in the UI.
func TestTakeLicense_LongestValidKeyWins(t *testing.T) {
	fromEnv := issue(t, PlanEnterprise, 24*time.Hour)

	sut := selfHosted(t, fromEnv)
	renewed := issue(t, PlanEnterprise, year)
	require.NoError(t, sut.takeLicense(renewed))
	assert.Equal(t, renewed, sut.license.Key(), "the renewed key from the UI wins")

	sut = selfHosted(t, fromEnv)
	require.ErrorIs(t, sut.takeLicense(issue(t, PlanEnterprise, time.Hour)), ErrLicenseShorter)
	assert.Equal(t, fromEnv, sut.license.Key(), "a shorter stored key never replaces the env key")

	sut = selfHosted(t, issue(t, PlanEnterprise, 0))
	require.ErrorIs(t, sut.takeLicense(renewed), ErrLicenseShorter, "nothing outlasts a key that never expires")
}

func TestTakeLicense_KeepsAnExpiredKey(t *testing.T) {
	sut := selfHosted(t, issue(t, PlanEnterprise, -time.Hour))

	require.NotNil(t, sut.License(), "an expired key still carries the retention hold")
	assert.True(t, sut.License().IsExpired())
}
