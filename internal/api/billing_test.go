package api

import (
	"context"
	"testing"
	"time"

	"github.com/mizuchilabs/kata/licx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

// TestFeaturesProto_CoversTheCatalog guards the defect where a feature is
// enforced by the guard but absent from the billing payload, which leaves
// every client unable to show it whatever the plan.
func TestFeaturesProto_CoversTheCatalog(t *testing.T) {
	features := featuresProto(entitlement.Plan{})

	for _, feature := range entitlement.CatalogFeatures {
		if _, ok := features[feature.Code]; !ok {
			t.Errorf("feature %q is in the catalog but missing from the billing payload", feature)
		}
	}
}

// TestFeaturesProto_EnterpriseLicenseEnablesStreaming is the reported bug: a
// self-hosted instance with a valid Enterprise license must see streaming.
func TestFeaturesProto_EnterpriseLicenseEnablesStreaming(t *testing.T) {
	ctx := context.Background()

	licensed := entitlement.NewService(
		noSubscription{},
		&licx.Claims{Plan: entitlement.PlanEnterprise},
		entitlement.ModeSelfHosted,
	)
	if !featuresProto(licensed.Resolve(ctx, "ws1"))[entitlement.FeatureAuditStreaming] {
		t.Error("audit_streaming is false with a valid Enterprise license")
	}

	// Without a license the same instance resolves to Community, which does
	// not include streaming.
	unlicensed := entitlement.NewService(noSubscription{}, nil, entitlement.ModeSelfHosted)
	if featuresProto(unlicensed.Resolve(ctx, "ws1"))[entitlement.FeatureAuditStreaming] {
		t.Error("audit_streaming is true without any license")
	}
}

// noSubscription reports the workspace has no subscription row, the normal
// Community case. The transaction short-circuits with ErrNoSubscription,
// which is exactly what the resolver treats as "no row".
type noSubscription struct{}

func (noSubscription) WithTx(_ context.Context, _ func(*db.Queries) error) error {
	return entitlement.ErrNoSubscription
}

// TestActivateLicense_AppliesWithoutRestart runs the real queries: the key
// lands in the database, applies at once, and another replica finds it.
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

	// Its own entitlement service, so the shared test server stays unlicensed.
	local := *cfg
	local.Entitlements = entitlement.NewService(cfg.Conn, nil, entitlement.ModeSelfHosted)
	sut := newBillingService(&local)

	before, err := sut.GetLicense(ctx, &nokkuv1.GetLicenseRequest{})
	require.NoError(t, err)
	require.False(t, before.GetActive())

	_, err = sut.ActivateLicense(ctx, &nokkuv1.ActivateLicenseRequest{Key: &key})
	require.NoError(t, err)

	after, err := sut.GetLicense(ctx, &nokkuv1.GetLicenseRequest{})
	require.NoError(t, err)
	assert.True(t, after.GetActive(), "the key must apply without a restart")
	assert.Equal(t, entitlement.PlanEnterprise, after.GetPlan())

	replica := entitlement.NewService(cfg.Conn, nil, entitlement.ModeSelfHosted)
	replica.WatchLicense(ctx)
	require.NotNil(t, replica.License(), "another replica must find the stored key")
	assert.False(t, replica.License().IsExpired())
}
