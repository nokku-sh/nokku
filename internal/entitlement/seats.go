package entitlement

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
)

type seatLimitError struct {
	Plan string
	Cap  int64
}

func (e *seatLimitError) Error() string {
	if e.Plan == PlanCommunity {
		return fmt.Sprintf("your plan includes %d members; upgrade to add more", e.Cap)
	}
	return fmt.Sprintf("all %d seats are in use; add seats under Billing to invite more", e.Cap)
}

// CanInvite is shared by the invitation, SSO, and SCIM join paths.
func (s *Service) CanInvite(ctx context.Context, workspaceID string, used int64) error {
	plan := s.Resolve(ctx, workspaceID)
	if plan.SeatCap != unlimited && used >= plan.SeatCap {
		slog.Warn(
			"seat cap reached",
			"plan",
			plan.Name,
			"cap",
			plan.SeatCap,
			"workspace_id",
			workspaceID,
		)
		return connect.NewError(connect.CodeResourceExhausted, &seatLimitError{
			Plan: plan.Name,
			Cap:  plan.SeatCap,
		})
	}
	return nil
}
