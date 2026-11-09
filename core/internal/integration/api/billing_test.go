//go:build integration

package api_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"

	"github.com/mizuchilabs/inkan/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

// The mode entitlement.New takes, named so the calls read.
const modeSelfHosted = false

// newSigner is a license server of its own. A service with pubHex takes its keys.
func newSigner(t *testing.T) (pubHex string, sign func(license.Claims) string) {
	t.Helper()
	privB64, pubHex, err := license.GenerateKey()
	require.NoError(t, err)
	priv, err := license.ParsePrivateKey(privB64)
	require.NoError(t, err)
	return pubHex, func(claims license.Claims) string {
		key, err := license.Issue("NOKKU", claims, priv)
		require.NoError(t, err)
		return key
	}
}

// issueLicense signs a year of Enterprise. A server with pubHex takes key.
func issueLicense(t *testing.T) (pubHex, key string) {
	t.Helper()
	pubHex, sign := newSigner(t)
	return pubHex, sign(license.Claims{Plan: entitlement.PlanEnterprise, ExpiresAt: time.Now().AddDate(1, 0, 0).Unix()})
}

// The key lands in the database, applies at once, and a restart finds it.
func TestActivateLicense_AppliesWithoutRestart(t *testing.T) {
	cfg, _ := newTestAPI(t)
	ctx := t.Context()

	pubHex, key := issueLicense(t)
	keepLicense(t, cfg)

	// Its own entitlement service, so the shared one stays unlicensed.
	local := *cfg
	var err error
	local.Entitlements, err = entitlement.New(ctx, cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	srv := httptest.NewServer(serving(api.New(&local).Handler(ctx)))
	t.Cleanup(srv.Close)
	owner := seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	sut := nokkuv1connect.NewBillingServiceClient(
		clientOn(srv, header("Authorization", "Bearer "+owner)),
	)

	_, err = sut.ActivateLicense(ctx, &nokkuv1.ActivateLicenseRequest{Key: &key})
	require.NoError(t, err)

	after, err := sut.GetLicense(ctx, &nokkuv1.GetLicenseRequest{})
	require.NoError(t, err)
	assert.True(t, after.GetActive(), "the key must apply without a restart")
	assert.Equal(t, entitlement.PlanEnterprise, after.GetPlan())
	// The reported bug: a valid license must show what the plan adds.
	billing, err := sut.GetBilling(ctx, &nokkuv1.GetBillingRequest{})
	require.NoError(t, err)
	assert.True(t, billing.GetFeatures()[entitlement.FeatureSCIM])

	restarted, err := entitlement.New(ctx, cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	st, err := restarted.Status(ctx, testWorkspace.ID)
	require.NoError(t, err)
	require.NotNil(t, st.License, "a restart must find the stored key")
	assert.False(t, st.License.IsExpired())
}

// Each workspace holds a key of its own, another one stays as it was.
func TestActivateLicense_IsPerWorkspace(t *testing.T) {
	cfg, _ := newTestAPI(t)
	ctx := t.Context()
	pubHex, key := issueLicense(t)
	sut, err := entitlement.New(ctx, cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	licensed, other := seedOtherWorkspace(t, cfg), seedOtherWorkspace(t, cfg)

	require.NoError(t, sut.ActivateLicense(ctx, licensed, key))

	assert.Equal(t, entitlement.PlanEnterprise, sut.Resolve(ctx, licensed).Name)
	assert.Equal(t, entitlement.PlanCommunity, sut.Resolve(ctx, other).Name, "a key must not reach another workspace")
}

func TestActivateLicense_LongestValidKeyWins(t *testing.T) {
	cfg, _ := newTestAPI(t)
	ctx := t.Context()
	pubHex, sign := newSigner(t)
	sut, err := entitlement.New(ctx, cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	ws := seedOtherWorkspace(t, cfg)
	expiring := func(in time.Duration) string {
		return sign(license.Claims{Plan: entitlement.PlanEnterprise, ExpiresAt: time.Now().Add(in).Unix()})
	}

	require.NoError(t, sut.ActivateLicense(ctx, ws, expiring(24*time.Hour)))
	require.NoError(t, sut.ActivateLicense(ctx, ws, expiring(365*24*time.Hour)), "a renewal replaces the key")
	require.ErrorIs(t, sut.ActivateLicense(ctx, ws, expiring(48*time.Hour)), entitlement.ErrLicenseShorter,
		"an old key must not undo a renewal")

	require.NoError(t, sut.ActivateLicense(ctx, ws, sign(license.Claims{Plan: entitlement.PlanEnterprise})))
	assert.ErrorIs(t, sut.ActivateLicense(ctx, ws, expiring(2*365*24*time.Hour)), entitlement.ErrLicenseShorter,
		"nothing outlasts a key that never expires")
}

// The hosted service could not tell two workspaces on one license apart otherwise.
func TestActivateLicense_OneLicenseOneWorkspace(t *testing.T) {
	cfg, _ := newTestAPI(t)
	ctx := t.Context()
	pubHex, sign := newSigner(t)
	sut, err := entitlement.New(ctx, cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	key := sign(license.Claims{
		ID: "sub_" + uuid.New().String(), Plan: entitlement.PlanEnterprise,
		ExpiresAt: time.Now().AddDate(1, 0, 0).Unix(),
	})
	first, second := seedOtherWorkspace(t, cfg), seedOtherWorkspace(t, cfg)

	require.NoError(t, sut.ActivateLicense(ctx, first, key))
	require.NoError(t, sut.ActivateLicense(ctx, first, key), "activating it again in its own workspace is fine")
	assert.ErrorIs(t, sut.ActivateLicense(ctx, second, key), entitlement.ErrLicenseInUse)
}

// The seats signed into a Pro key are the members a workspace may have.
func TestCanInvite_StopsAtTheSeatsOfTheKey(t *testing.T) {
	cfg, _ := newTestAPI(t)
	ctx := t.Context()
	pubHex, sign := newSigner(t)
	sut, err := entitlement.New(ctx, cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	ws := seedOtherWorkspace(t, cfg)

	require.NoError(t, sut.CanInvite(ctx, ws, 4))
	require.ErrorContains(t, sut.CanInvite(ctx, ws, 5), "your plan includes 5 members")

	require.NoError(t, sut.ActivateLicense(ctx, ws, sign(license.Claims{
		Plan: entitlement.PlanPro, ExpiresAt: time.Now().AddDate(1, 0, 0).Unix(),
		Meta: map[string]string{"seats": "12"},
	})))
	require.NoError(t, sut.CanInvite(ctx, ws, 11))
	assert.ErrorContains(t, sut.CanInvite(ctx, ws, 12), "all 12 seats are in use")
}

func TestUseEnvKey_StoresTheKey(t *testing.T) {
	cfg, _ := newTestAPI(t)
	pubHex, key := issueLicense(t)
	t.Setenv("NOKKU_LICENSE_KEY", key)
	sut, err := entitlement.New(t.Context(), cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	ws := seedOtherWorkspace(t, cfg)

	sut.UseEnvKey(t.Context(), ws)

	assert.Equal(t, entitlement.PlanEnterprise, sut.Resolve(t.Context(), ws).Name)
}

func TestUseEnvKey_RejectedKeyNeverStopsTheStart(t *testing.T) {
	cfg, _ := newTestAPI(t)
	_, pubHex, err := license.GenerateKey()
	require.NoError(t, err)
	t.Setenv("NOKKU_LICENSE_KEY", "NOKKU-AAAAA-BBBBB")
	sut, err := entitlement.New(t.Context(), cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	ws := seedOtherWorkspace(t, cfg)

	sut.UseEnvKey(t.Context(), ws)

	st, err := sut.Status(t.Context(), ws)
	require.NoError(t, err)
	assert.Nil(t, st.License, "a key that does not verify must not be held")
}

// An outage hands out no paid feature, keeps signing and tells the purge jobs to wait.
func TestStatus_AnOutageIsCommunity(t *testing.T) {
	ctx, cutOff := context.WithCancel(t.Context())
	conn, err := db.NewConnection(ctx)
	require.NoError(t, err)
	services := map[string]*entitlement.Service{}
	for name, mode := range map[string]bool{"self-hosted": modeSelfHosted, "hosted": !modeSelfHosted} {
		services[name], err = entitlement.New(t.Context(), conn, "", mode)
		require.NoError(t, err)
	}
	cutOff()
	require.Eventually(t, func() bool {
		_, err := services["hosted"].Status(t.Context(), testWorkspace.ID)
		return err != nil
	}, 5*time.Second, 10*time.Millisecond, "the closed pools still answer")

	for name, sut := range services {
		st, err := sut.Status(t.Context(), testWorkspace.ID)
		require.Error(t, err, "%s: the purge jobs skip on this error, an outage must never delete data", name)
		assert.Equal(t, entitlement.PlanCommunity, st.Plan.Name, "%s: no paid feature, and signing carries on", name)
		assert.Equal(t, entitlement.PlanCommunity, st.Keep.Name, name)
	}
	st, _ := services["self-hosted"].Status(t.Context(), testWorkspace.ID)
	assert.EqualValues(t, -1, st.Plan.ResourceCap, "an outage must not cap a self-hosted server")
}
