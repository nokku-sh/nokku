package entitlement

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
)

type SeatLimitError struct {
	Plan string
	Cap  int64
}

func (e *SeatLimitError) Error() string {
	return fmt.Sprintf(
		"your plan includes %d members; upgrade to add more",
		e.Cap,
	)
}

// CanInvite is shared by the invitation, SSO, and SCIM join paths.
func (s *Service) CanInvite(ctx context.Context, workspaceID string, used int64) error {
	plan := s.Resolve(ctx, workspaceID)
	if plan.SeatCap != Unlimited && used >= plan.SeatCap {
		slog.Warn(
			"seat cap reached",
			"plan",
			plan.Name,
			"cap",
			plan.SeatCap,
			"workspace_id",
			workspaceID,
		)
		return connect.NewError(connect.CodeResourceExhausted, &SeatLimitError{
			Plan: plan.Name,
			Cap:  plan.SeatCap,
		})
	}
	return nil
}
