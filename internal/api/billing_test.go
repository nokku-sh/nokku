package api

import (
	"context"
	"testing"

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

	licensed := entitlement.NewService(noSubscription{}, entitlement.PlanEnterprise, entitlement.ModeSelfHosted)
	if !featuresProto(licensed.Resolve(ctx, "ws1"))[entitlement.FeatureAuditStreaming] {
		t.Error("audit_streaming is false with a valid Enterprise license")
	}

	// Without a license the same instance resolves to Community, which does
	// not include streaming.
	unlicensed := entitlement.NewService(noSubscription{}, "", entitlement.ModeSelfHosted)
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
