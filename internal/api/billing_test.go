package api

import (
	"context"
	"testing"

	"github.com/mizuchilabs/kata/licx"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

// The mode entitlement.NewService takes, named so the calls read.
const modeSelfHosted = false

// A feature the guard enforces but the billing payload lacks leaves every client unable to show it.
func TestFeaturesProto_CoversTheCatalog(t *testing.T) {
	features := featuresProto(entitlement.Plan{})

	for _, feature := range entitlement.CatalogFeatures {
		if _, ok := features[feature.Code]; !ok {
			t.Errorf("feature %q is in the catalog but missing from the billing payload", feature)
		}
	}
}

// The reported bug: a self-hosted instance with a valid Enterprise license must see streaming.
func TestFeaturesProto_EnterpriseLicenseEnablesStreaming(t *testing.T) {
	ctx := t.Context()

	licensed := entitlement.NewService(
		noSubscription{},
		&licx.Claims{Plan: entitlement.PlanEnterprise},
		modeSelfHosted,
	)
	if !featuresProto(licensed.Resolve(ctx, "ws1"))[entitlement.FeatureAuditStreaming] {
		t.Error("audit_streaming is false with a valid Enterprise license")
	}

	// Without a license the same instance resolves to Community, which does not include streaming.
	unlicensed := entitlement.NewService(noSubscription{}, nil, modeSelfHosted)
	if featuresProto(unlicensed.Resolve(ctx, "ws1"))[entitlement.FeatureAuditStreaming] {
		t.Error("audit_streaming is true without any license")
	}
}

// noSubscription is the normal Community case, the resolver reads ErrNoSubscription as no row.
type noSubscription struct{}

func (noSubscription) SysTx(_ context.Context, _ func(*db.Queries) error) error {
	return entitlement.ErrNoSubscription
}
