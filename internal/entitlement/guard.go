package entitlement

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/actor"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
)

// UpgradeURL is shown to admins who hit a plan gate. Keep it in one place
// so the pricing page can move freely.
const UpgradeURL = "https://nokku.sh/pricing"

// procedureFeatures gates whole procedures behind a plan feature. Any
// request to a listed route is denied with PermissionDenied when the
// workspace's plan lacks the feature.
//
// Keep this map the ONLY place routes are gated: handlers must never
// import plan logic (§5.2). The golden test in guard_test.go fails when a
// catalog feature has no wiring here or in conditionalRules.
var procedureFeatures = map[string]string{
	// Audit export feeds SIEMs and auditor evidence packs: a paid
	// evidence feature, not a daily-driver feature.
	nokkuv1connect.UtilServiceExportAuditLogsProcedure: FeatureAuditExport,
}

// featureLabels are the human-facing names used in denial messages.
var featureLabels = map[string]string{
	FeatureOIDC:        "OIDC single sign-on",
	FeatureEnforceSSO:  "enforced single sign-on",
	FeatureSAML:        "SAML single sign-on",
	FeatureAuditExport: "audit log export",
	FeatureExternalKMS: "external key management",
}

// GuardInterceptor enforces plan features at the route level. It runs
// after authentication and authorization, pinning its plan resolutions to
// the request context so downstream handlers reuse them.
type GuardInterceptor struct {
	ent *Service
}

func NewGuardInterceptor(ent *Service) *GuardInterceptor {
	return &GuardInterceptor{ent: ent}
}

func (g *GuardInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx = WithRequestCache(ctx)
		if err := g.check(ctx, req.Spec().Procedure, req.Any()); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (g *GuardInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler passes streaming procedures through. Every gated
// route today is unary; add streaming checks here when that changes.
func (g *GuardInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

// check denies the request when its route or payload requires a feature
// the workspace's plan does not include. Requests without a pinned
// workspace (system calls, pre-tenant procedures) pass through; the
// authorization interceptor owns that boundary.
func (g *GuardInterceptor) check(ctx context.Context, procedure string, msg any) error {
	feature, gated := procedureFeatures[procedure]
	if !gated {
		feature, gated = conditionalFeature(procedure, msg)
	}
	if !gated {
		return nil
	}

	workspaceID := actor.WorkspaceIDFromContext(ctx)
	if workspaceID == "" {
		return nil
	}
	if g.ent.Has(ctx, workspaceID, feature) {
		return nil
	}
	return g.deny(ctx, workspaceID, feature)
}

// conditionalFeature gates procedures where only part of the payload
// exercises the feature. Turning a feature OFF must always work: a
// downgrade or an admin cleaning up must never be blocked by the paywall
// it created.
func conditionalFeature(procedure string, msg any) (string, bool) {
	req, ok := msg.(*nokkuv1.UpdateSSOProviderRequest)
	if !ok || procedure != nokkuv1connect.SSOServiceUpdateSSOProviderProcedure {
		return "", false
	}

	switch req.GetMethod() {
	case "saml":
		if req.GetIsActive() {
			return FeatureSAML, true
		}
	case "oidc":
		if req.GetEnforceSso() {
			return FeatureEnforceSSO, true
		}
	}
	return "", false
}

// deny returns PermissionDenied with machine-readable metadata so the UI
// can render a proper "Available in Pro" affordance instead of a raw
// error. The paywall becomes a feature tour.
func (g *GuardInterceptor) deny(ctx context.Context, workspaceID, feature string) error {
	plan := g.ent.Resolve(ctx, workspaceID)

	err := connect.NewError(
		connect.CodePermissionDenied,
		fmt.Errorf("%s is not available on the %s plan", featureLabel(feature), displayName(plan.Name)),
	)
	err.Meta().Set("x-nokku-plan", plan.Name)
	err.Meta().Set("x-nokku-feature", feature)
	err.Meta().Set("x-nokku-upgrade", UpgradeURL)
	return err
}

func featureLabel(feature string) string {
	if label, ok := featureLabels[feature]; ok {
		return label
	}
	return feature
}

// displayName maps internal plan names to their marketed names.
func displayName(plan string) string {
	switch plan {
	case PlanCommunity:
		return "Community"
	case PlanPro:
		return "Pro"
	case PlanEnterprise:
		return "Enterprise"
	}
	return plan
}
