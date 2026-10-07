package entitlement

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/actor"
)

const upgradeURL = "https://nokku.sh/pricing"

// procedureFeatures is the only place routes are gated, handlers never import
// plan logic. guard_test.go fails when a catalog feature has no wiring here
// or in conditionalFeature.
var procedureFeatures = map[string]string{
	nokkuv1connect.UtilServiceExportAuditLogsProcedure: FeatureAuditExport,
	// Listing and revoking must keep working after a downgrade.
	nokkuv1connect.SCIMServiceCreateSCIMTokenProcedure: FeatureSCIM,
}

// cappedCreate is the only place resource caps are wired, guard_test.go fails
// when a create procedure is missing without an exemption. Seats are checked
// in CanInvite. EnrollDaemon is gated in its handler since the workspace only
// comes from the enroll token.
var cappedCreate = map[string]bool{
	nokkuv1connect.TargetServiceCreateTargetProcedure:                    true,
	nokkuv1connect.TeamServiceCreateTeamProcedure:                        true,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure:    true,
	nokkuv1connect.CertificateServiceCreateCertificateAuthorityProcedure: true,
}

// GuardInterceptor caches plan resolutions on the context for handlers to reuse.
type GuardInterceptor struct {
	ent *Service
}

func NewGuardInterceptor(ent *Service) *GuardInterceptor {
	return &GuardInterceptor{ent: ent}
}

func (g *GuardInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx = withRequestCache(ctx)
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

// WrapStreamingHandler passes through, every gated route is unary.
func (g *GuardInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

// check passes unpinned requests, the authz interceptor owns that boundary.
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

// conditionalFeature never gates turning a feature off, a downgraded
// workspace must be able to clean up.
func conditionalFeature(procedure string, msg any) (string, bool) {
	req, ok := msg.(*nokkuv1.UpdateWorkspaceRequest)
	if !ok || procedure != nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure {
		return "", false
	}
	settings := req.GetSettings()
	if settings.GetAuditWebhookUrl() != "" || settings.GetAuditWebhookSecret() != "" {
		return FeatureAuditStreaming, true
	}
	if settings.GetEnforceSso() {
		return FeatureEnforceSSO, true
	}
	return "", false
}

// deny carries metadata so the UI can render an upgrade prompt.
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
	err.Meta().Set("x-nokku-upgrade", upgradeURL)
	return err
}

func featureLabel(code string) string {
	if f, ok := featureInCatalog(code); ok {
		return f.Label
	}
	return code
}

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
