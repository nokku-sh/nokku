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
	nokkuv1connect.UtilServiceExportAuditLogsProcedure: FeatureAuditExport,
	// Only minting is gated: listing and revoking must always work so a
	// downgrade or cleanup is never blocked by the paywall it created.
	nokkuv1connect.SCIMServiceCreateSCIMTokenProcedure: FeatureSCIM,
}

// cappedCreate gates create procedures behind the plan's pooled resource
// cap (quota.go CheckResources). ResourceExhausted, fail open — the quota
// counterpart of procedureFeatures, and equally the ONLY place resource
// caps are wired: the companion golden test in guard_test.go fails when a
// create procedure is missing here or lacks a documented exemption.
//
// Seats are deliberately absent: they are the per-seat-billed dimension
// with bespoke denial semantics, checked in CanInvite (seats.go).
// DaemonServiceEnrollDaemon is gated in the handler instead: enrollment is
// a public endpoint whose workspace comes from the enroll token, so the
// guard interceptor cannot see it pinned in the request context.
var cappedCreate = map[string]bool{
	nokkuv1connect.TargetServiceCreateTargetProcedure:                    true,
	nokkuv1connect.TeamServiceCreateTeamProcedure:                        true,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure:    true,
	nokkuv1connect.CertificateServiceCreateCertificateAuthorityProcedure: true,
	nokkuv1connect.WorkspaceDomainServiceCreateWorkspaceDomainProcedure:  true,
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
		procedure := req.Spec().Procedure
		if err := g.check(ctx, procedure, req.Any()); err != nil {
			return nil, err
		}
		if err := g.checkResources(ctx, procedure); err != nil {
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

// checkResources denies resource-capped create procedures when the
// workspace's pooled resource budget is exhausted. Unpinned contexts pass
// through (the authz interceptor owns that boundary); CheckResources owns
// the denial semantics (fail open, ResourceExhausted, quota metadata).
func (g *GuardInterceptor) checkResources(ctx context.Context, procedure string) error {
	if !cappedCreate[procedure] {
		return nil
	}
	workspaceID := actor.WorkspaceIDFromContext(ctx)
	if workspaceID == "" {
		return nil
	}
	return g.ent.CheckResources(ctx, workspaceID)
}

// conditionalFeature gates procedures where only part of the payload
// exercises the feature. Turning a feature OFF must always work: a
// downgrade or an admin cleaning up must never be blocked by the paywall
// it created.
func conditionalFeature(procedure string, msg any) (string, bool) {
	if req, ok := msg.(*nokkuv1.UpdateWorkspaceRequest); ok &&
		procedure == nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure {
		// Streaming is configured on the workspace settings, so only the two
		// fields that turn it on are gated. Clearing them works on any plan,
		// which keeps a downgraded workspace able to switch the stream off.
		settings := req.GetSettings()
		if settings.GetAuditWebhookUrl() != "" || settings.GetAuditWebhookSecret() != "" {
			return FeatureAuditStreaming, true
		}
		return "", false
	}

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
		fmt.Errorf(
			"%s is not available on the %s plan",
			featureLabel(feature),
			displayName(plan.Name),
		),
	)
	err.Meta().Set("x-nokku-plan", plan.Name)
	err.Meta().Set("x-nokku-feature", feature)
	err.Meta().Set("x-nokku-upgrade", UpgradeURL)
	return err
}

func featureLabel(code string) string {
	if f, ok := featureInCatalog(code); ok {
		return f.Label
	}
	return code
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
