package entitlement

import (
	"cmp"
	"context"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
)

// CheckFeatures passes an unpinned call, authz owns that boundary.
func (s *Service) CheckFeatures(ctx context.Context, features []string) error {
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
			return connect.Errorf(connect.CodePermissionDenied,
				"%s is not available on the %s plan", featureLabel(feature), cmp.Or(PlanNames[plan.Name], plan.Name))
		}
	}
	return nil
}

// CheckSigning is for user certificates. Host certs and daemon syncs carry on.
func (s *Service) CheckSigning(ctx context.Context) error {
	workspaceID := actor.WorkspaceIDFromContext(ctx)
	if workspaceID == "" || s.Resolve(ctx, workspaceID).Name != PlanInactive {
		return nil
	}
	return errInactive()
}

// RequestedFeatures never gates turning one off, a downgrade must clean up.
func RequestedFeatures(msg any) []string {
	var features []string
	switch req := msg.(type) {
	case *nokkuv1.UpdateWorkspaceRequest:
		if req.GetSettings().GetEnforceSso() {
			features = append(features, FeatureEnforceSSO)
		}
	case *nokkuv1.UpdateDaemonDefaultsRequest:
		if req.GetSessionIdleTimeout().AsDuration() > 0 {
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
