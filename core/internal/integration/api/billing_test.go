//go:build integration

package api_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/mizuchilabs/inkan/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

// The mode entitlement.New takes, named so the calls read.
const modeSelfHosted = false

// issueLicense makes a signing key and a year's license for plan. A server built with pubHex accepts key.
func issueLicense(t *testing.T, plan string) (pubHex, key string) {
	t.Helper()
	privB64, pubHex, err := license.GenerateKey()
	require.NoError(t, err)
	priv, err := license.ParsePrivateKey(privB64)
	require.NoError(t, err)
	key, err = license.Issue("NOKKU", license.Claims{Plan: plan, ExpiresAt: time.Now().AddDate(1, 0, 0).Unix()}, priv)
	require.NoError(t, err)
	return pubHex, key
}

// The real queries: the key lands in the database, applies at once, and a restart finds it.
func TestActivateLicense_AppliesWithoutRestart(t *testing.T) {
	cfg, _ := newTestAPI(t)
	ctx := t.Context()

	pubHex, key := issueLicense(t, entitlement.PlanEnterprise)

	// A server with its own entitlement service, so the shared one stays unlicensed.
	local := *cfg
	var err error
	local.Entitlements, err = entitlement.New(ctx, cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	srv := httptest.NewServer(api.New(&local).Handler(ctx))
	t.Cleanup(srv.Close)
	owner := seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	sut := nokkuv1connect.NewBillingServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), header("Authorization", "Bearer "+owner)),
	)

	before, err := sut.GetLicense(ctx, &nokkuv1.GetLicenseRequest{})
	require.NoError(t, err)
	require.False(t, before.GetActive())
	billing, err := sut.GetBilling(ctx, &nokkuv1.GetBillingRequest{})
	require.NoError(t, err)
	require.False(t, billing.GetFeatures()[entitlement.FeatureSCIM], "Community has no SCIM")

	_, err = sut.ActivateLicense(ctx, &nokkuv1.ActivateLicenseRequest{Key: &key})
	require.NoError(t, err)

	after, err := sut.GetLicense(ctx, &nokkuv1.GetLicenseRequest{})
	require.NoError(t, err)
	assert.True(t, after.GetActive(), "the key must apply without a restart")
	assert.Equal(t, entitlement.PlanEnterprise, after.GetPlan())
	// The reported bug: a self-hosted instance with a valid Enterprise license must see what the plan adds.
	billing, err = sut.GetBilling(ctx, &nokkuv1.GetBillingRequest{})
	require.NoError(t, err)
	assert.True(t, billing.GetFeatures()[entitlement.FeatureSCIM])

	restarted, err := entitlement.New(ctx, cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	require.NotNil(t, restarted.License(), "a restart must find the stored key")
	assert.False(t, restarted.License().IsExpired())
}

func TestLicense_RejectedEnvKeyNeverStopsTheStart(t *testing.T) {
	cfg, _ := newTestAPI(t)
	_, pubHex, err := license.GenerateKey()
	require.NoError(t, err)
	t.Setenv("NOKKU_LICENSE_KEY", "NOKKU-AAAAA-BBBBB")

	sut, err := entitlement.New(t.Context(), cfg.Conn, pubHex, modeSelfHosted)

	require.NoError(t, err)
	assert.Nil(t, sut.License(), "neither the env key nor a key of another signer may be held")
}
