package entitlement

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
)

// procedureFeatures is the only place routes are gated. guard_test.go fails on a catalog feature with no wiring.
var procedureFeatures = map[string]string{
	nokkuv1connect.UtilServiceExportAuditLogsProcedure: FeatureAuditExport,
	// Listing and revoking must keep working after a downgrade.
	nokkuv1connect.SCIMServiceCreateSCIMTokenProcedure: FeatureSCIM,
}

// cappedCreate is the only place resource caps are wired. Seats are checked in CanInvite, EnrollDaemon in its handler.
var cappedCreate = map[string]bool{
	nokkuv1connect.TargetServiceCreateTargetProcedure:                    true,
	nokkuv1connect.TeamServiceCreateTeamProcedure:                        true,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure:    true,
	nokkuv1connect.CertificateServiceCreateCertificateAuthorityProcedure: true,
}

// NewGuardInterceptor gates features and caps creates. Every gated route is unary, streams pass through.
func NewGuardInterceptor(ent *Service) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure
			if err := ent.checkFeature(ctx, procedure, req.Any()); err != nil {
				return nil, err
			}
			if err := ent.checkCap(ctx, procedure); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}
	}
}

// checkFeature passes unpinned requests, the authz interceptor owns that boundary.
func (s *Service) checkFeature(ctx context.Context, procedure string, msg any) error {
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
	plan := s.Resolve(ctx, workspaceID)
	if plan.Has(feature) {
		return nil
	}
	return connect.NewError(connect.CodePermissionDenied, fmt.Errorf(
		"%s is not available on the %s plan", featureLabel(feature), displayName(plan.Name)))
}

func (s *Service) checkCap(ctx context.Context, procedure string) error {
	if !cappedCreate[procedure] {
		return nil
	}
	workspaceID := actor.WorkspaceIDFromContext(ctx)
	if workspaceID == "" {
		return nil
	}
	return s.CheckResources(ctx, workspaceID)
}

// conditionalFeature never gates turning a feature off, a downgraded workspace must be able to clean up.
func conditionalFeature(procedure string, msg any) (string, bool) {
	req, ok := msg.(*nokkuv1.UpdateWorkspaceRequest)
	if !ok || procedure != nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure {
		return "", false
	}
	if req.GetSettings().GetEnforceSso() {
		return FeatureEnforceSSO, true
	}
	return "", false
}

func featureLabel(code string) string {
	for _, f := range CatalogFeatures {
		if f.Code == code {
			return f.Label
		}
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
