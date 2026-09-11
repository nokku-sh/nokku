package api

import (
	"context"
	"testing"

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

	licensed := entitlement.NewService(noSubscription{}, enterpriseLicense{}, entitlement.ModeSelfHosted)
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

type noSubscription struct{}

func (noSubscription) Subscription(
	context.Context,
	string,
) (string, entitlement.Status, error) {
	return "", "", entitlement.ErrNoSubscription
}

func (noSubscription) ResourceCount(context.Context, string) (int64, error) {
	return 0, nil
}

type enterpriseLicense struct{}

func (enterpriseLicense) Valid() bool { return true }

func (enterpriseLicense) LicensedPlan() string { return entitlement.PlanEnterprise }
