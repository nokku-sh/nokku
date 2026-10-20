package entitlement

import (
	"context"
	"fmt"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
)

// procedureFeatures is the only place routes are gated. guard_test.go fails on a catalog feature with no wiring.
var procedureFeatures = map[string]string{
	nokkuv1connect.UtilServiceExportAuditLogsProcedure:      FeatureAuditExport,
	nokkuv1connect.UtilServiceExportAccessReportProcedure:   FeatureAccessReview,
	nokkuv1connect.SCIMServiceCreateSCIMTokenProcedure:      FeatureSCIM,
	nokkuv1connect.LegalHoldServiceCreateLegalHoldProcedure: FeatureLegalHold,
	// Asking, approving and finding what to ask for. Listing, denying and cancelling stay, so a lapsed plan can clean up.
	nokkuv1connect.AccessRequestServiceCreateAccessRequestProcedure:     FeatureAccessRequests,
	nokkuv1connect.AccessRequestServiceApproveAccessRequestProcedure:    FeatureAccessRequests,
	nokkuv1connect.AccessRequestServiceListRequestableAccountsProcedure: FeatureAccessRequests,
	nokkuv1connect.AuditStreamServiceCreateAuditStreamProcedure:         FeatureAuditStreaming,
	nokkuv1connect.AuditStreamServiceTestAuditStreamProcedure:           FeatureAuditStreaming,
}

// cappedCreate is the only place resource caps are wired. Seats are checked in CanInvite, EnrollDaemon in its handler.
var cappedCreate = map[string]bool{
	nokkuv1connect.TargetServiceCreateTargetProcedure:                    true,
	nokkuv1connect.TeamServiceCreateTeamProcedure:                        true,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure:    true,
	nokkuv1connect.CertificateServiceCreateCertificateAuthorityProcedure: true,
}

// signing is every route that signs a user certificate. An inactive workspace gets none, its host certificates and
// daemon syncs carry on.
var signing = map[string]bool{
	nokkuv1connect.CertificateServiceSignSSHCertificateProcedure: true,
	nokkuv1connect.DaemonServiceCreateSessionProcedure:           true,
}

// NewGuardInterceptor gates features and caps creates. Every gated route is unary, streams pass through.
func NewGuardInterceptor(ent *Service) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure
			if err := ent.checkFeature(ctx, procedure, req.Any()); err != nil {
				return nil, err
			}
			if err := ent.checkSigning(ctx, procedure); err != nil {
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
	features := requestedFeatures(msg)
	if feature, gated := procedureFeatures[procedure]; gated {
		features = append(features, feature)
	}
	if len(features) == 0 {
		return nil
	}

	workspaceID := actor.WorkspaceIDFromContext(ctx)
	if workspaceID == "" {
		return nil
	}
	plan := s.Resolve(ctx, workspaceID)
	for _, feature := range features {
		if !plan.Has(feature) {
			return connect.NewError(connect.CodePermissionDenied, fmt.Errorf(
				"%s is not available on the %s plan", featureLabel(feature), displayName(plan.Name)))
		}
	}
	return nil
}

func (s *Service) checkSigning(ctx context.Context, procedure string) error {
	if !signing[procedure] {
		return nil
	}
	workspaceID := actor.WorkspaceIDFromContext(ctx)
	if workspaceID == "" || s.Resolve(ctx, workspaceID).Name != PlanInactive {
		return nil
	}
	return errInactive()
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

// requestedFeatures lists every feature a request turns on. It never gates turning one off, a downgraded workspace
// must be able to clean up.
func requestedFeatures(msg any) []string {
	var features []string
	switch req := msg.(type) {
	case *nokkuv1.UpdateWorkspaceRequest:
		if req.GetSettings().GetEnforceSso() {
			features = append(features, FeatureEnforceSSO)
		}
		if req.GetSettings().GetSessionIdleTimeout().AsDuration() > 0 {
			features = append(features, FeatureIdleTimeout)
		}
	case *nokkuv1.SetRequestableTagsRequest:
		if len(req.GetTags()) > 0 {
			features = append(features, FeatureAccessRequests)
		}
	case *nokkuv1.UpdateAuditStreamRequest:
		if req.GetEnabled() {
			features = append(features, FeatureAuditStreaming)
		}
	case *nokkuv1.AddSubjectsRequest:
		if req.GetExpiresAt() != nil {
			features = append(features, FeatureExpiringAccess)
		}
	}
	return features
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
	case PlanInactive:
		return "inactive"
	}
	return plan
}
