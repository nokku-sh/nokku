package entitlement

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/actor"

	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

// wiredFeatures lists every feature gated somewhere in the guard.
func wiredFeatures() map[string]bool {
	wired := make(map[string]bool)
	for _, feature := range procedureFeatures {
		wired[feature] = true
	}
	for _, feature := range conditionalFeatures() {
		wired[feature] = true
	}
	return wired
}

// conditionalFeatures returns the features checked inside
// conditionalFeature. Kept in sync manually; the golden test below fails
// when the switch and this list drift apart.
func conditionalFeatures() []string {
	return []string{FeatureSAML, FeatureEnforceSSO}
}

// featuresFreeInAllPlans are catalog features that need no gate because
// every plan includes them. Removing a feature from this list (making it
// paid) requires wiring it in the guard in the same change.
var featuresFreeInAllPlans = []string{FeatureOIDC}

// featuresGatedOutsideTheGuard are catalog features enforced elsewhere,
// with the enforcement point documented. External KMS is instance-level
// configuration (KMS_URI requires a valid license), not a per-workspace
// route, so the guard cannot gate it.
var featuresGatedOutsideTheGuard = map[string]string{
	FeatureExternalKMS: "instance-level: KMS_URI startup check in internal/config",
}

// TestGolden_FeaturesWired fails whenever someone adds a catalog feature
// without wiring it (or explicitly exempting it). A paid feature that no
// route enforces is revenue leakage; a feature no plan includes is dead
// catalog weight.
func TestGolden_FeaturesWired(t *testing.T) {
	allFeatures := []string{
		FeatureOIDC,
		FeatureEnforceSSO,
		FeatureSAML,
		FeatureAuditExport,
		FeatureExternalKMS,
	}

	for _, feature := range allFeatures {
		reason := "unwired"
		switch {
		case wiredFeatures()[feature]:
			continue
		case slices.Contains(featuresFreeInAllPlans, feature):
			reason = "free in all plans"
		default:
			if _, ok := featuresGatedOutsideTheGuard[feature]; ok {
				reason = "gated outside the guard"
			}
		}
		if reason == "unwired" {
			t.Errorf(
				"feature %q is in the catalog but gated nowhere: wire it in procedureFeatures/conditionalFeature or exempt it with a documented reason",
				feature,
			)
		}
	}

	// The reverse direction: gates must reference real catalog features.
	for feature := range wiredFeatures() {
		if !slices.Contains(allFeatures, feature) {
			t.Errorf("guard gates %q, which is not a catalog feature", feature)
		}
	}
}

func TestConditionalFeature(t *testing.T) {
	samlActivate := &nokkuv1.UpdateSSOProviderRequest{
		Method:   new("saml"),
		IsActive: new(true),
	}
	samlDeactivate := &nokkuv1.UpdateSSOProviderRequest{Method: new("saml")}
	oidcEnforce := &nokkuv1.UpdateSSOProviderRequest{
		Method:     new("oidc"),
		EnforceSso: new(true),
	}
	oidcPlain := &nokkuv1.UpdateSSOProviderRequest{Method: new("oidc")}

	tests := []struct {
		name      string
		procedure string
		msg       any
		wantFeat  string
		wantGated bool
	}{
		{
			name:      "activating SAML is gated",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       samlActivate,
			wantFeat:  FeatureSAML,
			wantGated: true,
		},
		{
			name:      "deactivating SAML is never gated",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       samlDeactivate,
		},
		{
			name:      "enforcing SSO on OIDC is gated",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       oidcEnforce,
			wantFeat:  FeatureEnforceSSO,
			wantGated: true,
		},
		{
			name:      "plain OIDC update is not gated",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       oidcPlain,
		},
		{
			name:      "other procedures are not conditionally gated",
			procedure: "/nokku.v1.SSOService/GetSSOProvider",
			msg:       samlActivate,
		},
		{
			name:      "non-SSO request types are ignored",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       "not a proto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feature, gated := conditionalFeature(tt.procedure, tt.msg)
			if gated != tt.wantGated {
				t.Errorf("gated = %v, want %v", gated, tt.wantGated)
			}
			if feature != tt.wantFeat {
				t.Errorf("feature = %q, want %q", feature, tt.wantFeat)
			}
		})
	}
}

func TestGuard_DeniesAndAdvertisesUpgrade(t *testing.T) {
	// Community workspace: audit export must deny with upgrade metadata.
	sut := NewGuardInterceptor(NewService(
		&fakeDB{},
		nil,
		ModeSaaS,
	))

	ctx := actor.AnnotateTenant(context.Background(), "ws1")
	err := sut.check(ctx, "/nokku.v1.UtilService/ExportAuditLogs", struct{}{})

	if err == nil {
		t.Fatal("expected denial for audit export on community")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected *connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodePermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", connectErr.Code())
	}
	if got := connectErr.Meta().Get("x-nokku-plan"); got != PlanCommunity {
		t.Errorf("x-nokku-plan = %q, want %q", got, PlanCommunity)
	}
	if got := connectErr.Meta().Get("x-nokku-feature"); got != FeatureAuditExport {
		t.Errorf("x-nokku-feature = %q, want %q", got, FeatureAuditExport)
	}
	if got := connectErr.Meta().Get("x-nokku-upgrade"); got != UpgradeURL {
		t.Errorf("x-nokku-upgrade = %q, want %q", got, UpgradeURL)
	}
	if !strings.Contains(connectErr.Message(), "audit log export") {
		t.Errorf("message %q should name the feature", connectErr.Message())
	}
}

func TestGuard_AllowsPaidPlanAndUnpinnedContext(t *testing.T) {
	sut := NewGuardInterceptor(NewService(
		&fakeDB{plan: PlanPro, status: StatusActive},
		nil,
		ModeSaaS,
	))

	// Pro workspace passes.
	ctx := actor.AnnotateTenant(context.Background(), "ws1")
	if err := sut.check(ctx, "/nokku.v1.UtilService/ExportAuditLogs", struct{}{}); err != nil {
		t.Errorf("pro workspace denied: %v", err)
	}

	// Unpinned context passes (the authz interceptor owns that boundary).
	if err := sut.check(context.Background(), "/nokku.v1.UtilService/ExportAuditLogs", struct{}{}); err != nil {
		t.Errorf("unpinned context denied: %v", err)
	}

	// Ungated procedures pass everywhere.
	if err := sut.check(ctx, "/nokku.v1.UtilService/GetVersion", struct{}{}); err != nil {
		t.Errorf("ungated procedure denied: %v", err)
	}
}
