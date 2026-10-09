//go:build integration

package api_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mizuchilabs/kata/licx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/api"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

// The mode entitlement.NewService takes, named so the calls read.
const modeSelfHosted = false

// The real queries: the key lands in the database, applies at once, and another replica finds it.
func TestActivateLicense_AppliesWithoutRestart(t *testing.T) {
	cfg, _ := newTestAPI(t)
	ctx := t.Context()

	privB64, pubHex, err := licx.GenerateKey()
	require.NoError(t, err)
	require.NoError(t, licx.SetPublicKey(pubHex))
	t.Cleanup(func() { _ = licx.SetPublicKey("") })
	priv, err := licx.ParsePrivateKey(privB64)
	require.NoError(t, err)
	key, err := licx.Issue("NOKKU", licx.Claims{
		Plan:      entitlement.PlanEnterprise,
		ExpiresAt: time.Now().AddDate(1, 0, 0).Unix(),
	}, priv)
	require.NoError(t, err)

	// A server with its own entitlement service, so the shared one stays unlicensed.
	local := *cfg
	local.Entitlements = entitlement.NewService(cfg.Conn, nil, modeSelfHosted)
	srv := httptest.NewServer(api.New(&local).Handler(ctx))
	t.Cleanup(srv.Close)
	owner := seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	sut := nokkuv1connect.NewBillingServiceClient(srv.Client(), srv.URL, header("Authorization", "Bearer "+owner))

	before, err := sut.GetLicense(ctx, &nokkuv1.GetLicenseRequest{})
	require.NoError(t, err)
	require.False(t, before.GetActive())

	_, err = sut.ActivateLicense(ctx, &nokkuv1.ActivateLicenseRequest{Key: &key})
	require.NoError(t, err)

	after, err := sut.GetLicense(ctx, &nokkuv1.GetLicenseRequest{})
	require.NoError(t, err)
	assert.True(t, after.GetActive(), "the key must apply without a restart")
	assert.Equal(t, entitlement.PlanEnterprise, after.GetPlan())

	replica := entitlement.NewService(cfg.Conn, nil, modeSelfHosted)
	replica.WatchLicense(ctx)
	require.NotNil(t, replica.License(), "another replica must find the stored key")
	assert.False(t, replica.License().IsExpired())
}
