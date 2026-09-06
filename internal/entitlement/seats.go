package entitlement

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
)

// SeatLimitError is the user-facing denial when a workspace is full.
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

// CanInvite reports whether one more member fits under the plan's seat
// cap. The only remaining quota check in the product, shared by the
// invitation and SCIM provisioning paths.
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
