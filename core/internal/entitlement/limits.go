package entitlement

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
)

func errInactive() error {
	return connect.NewError(connect.CodeFailedPrecondition,
		"this workspace has no active plan, the owner can subscribe under Billing")
}

// CanInvite is shared by the invitation, SSO, and SCIM join paths.
func (s *Service) CanInvite(ctx context.Context, workspaceID string, used int64) error {
	plan := s.Resolve(ctx, workspaceID)
	if plan.Name == PlanInactive {
		return errInactive()
	}
	if plan.SeatCap == unlimited || used < plan.SeatCap {
		return nil
	}
	slog.Warn("seat cap reached", "plan", plan.Name, "cap", plan.SeatCap, "workspace_id", workspaceID)
	if plan.Name == PlanCommunity {
		return connect.Errorf(connect.CodeResourceExhausted,
			"your plan includes %d members; upgrade to add more", plan.SeatCap)
	}
	return connect.Errorf(connect.CodeResourceExhausted,
		"all %d seats are in use; add seats under Billing to invite more", plan.SeatCap)
}

// CheckResources allows the create when the count cannot be read, quotas fail open.
func (s *Service) CheckResources(ctx context.Context, workspaceID string) error {
	plan := s.Resolve(ctx, workspaceID)
	if plan.Name == PlanInactive {
		return errInactive()
	}
	if plan.ResourceCap == unlimited {
		return nil
	}
	// Names the workspace, the count runs as nokku_system.
	used, err := s.conn.Sys().CountWorkspaceResources(ctx, workspaceID)
	if err != nil {
		slog.Error("resource count failed, allowing create", "error", err, "workspace_id", workspaceID)
		return nil
	}
	if used < plan.ResourceCap {
		return nil
	}
	return connect.Errorf(connect.CodeResourceExhausted,
		"your plan includes %d managed resources; delete some or upgrade to add more", plan.ResourceCap)
}
