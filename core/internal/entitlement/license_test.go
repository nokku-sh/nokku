package entitlement

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const year = 365 * day

// Every refusal comes before the store. internal/integration/api takes a key.
func TestActivateLicense_Refusals(t *testing.T) {
	ctx := t.Context()
	for _, sut := range []*Service{selfHosted, hosted} {
		require.ErrorIs(t, sut.ActivateLicense(ctx, "ws1", "NOKKU-AAAAA-BBBBB"), ErrLicenseInvalid)
		require.ErrorIs(t, sut.ActivateLicense(ctx, "ws1", issue(t, PlanPro, year)), ErrLicenseInvalid,
			"a Pro key must name its seats")
		require.ErrorIs(t, sut.ActivateLicense(ctx, "ws1", issueSeats(t, PlanPro, year, "ten")), ErrLicenseInvalid)
		require.ErrorIs(t, sut.ActivateLicense(ctx, "ws1", issueSeats(t, PlanPro, year, "0")), ErrLicenseInvalid)
		require.ErrorIs(t, sut.ActivateLicense(ctx, "ws1", issue(t, "team", year)), ErrLicenseInvalid)
		require.ErrorIs(t, sut.ActivateLicense(ctx, "ws1", issue(t, PlanEnterprise, -time.Hour)), ErrLicenseExpired)
	}

	require.ErrorIs(t, hosted.ActivateLicense(ctx, "ws1", issue(t, PlanEnterprise, year)), ErrLicenseInvalid,
		"a hosted key without a license id could unlock any number of workspaces")

	unbuilt := newService(nil, "", false)
	assert.ErrorIs(t, unbuilt.ActivateLicense(ctx, "ws1", issue(t, PlanEnterprise, year)), ErrLicenseUnsupported)
}

func TestRefreshLicense_OfflineAsksNothing(t *testing.T) {
	sut := newService(nil, testPublicKey, false)
	sut.offline = true
	assert.NoError(t, sut.RefreshLicense(t.Context(), "ws1"), "an offline server never reads the row or the network")
}
