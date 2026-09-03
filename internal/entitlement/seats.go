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

// Seats returns the current member count and the plan's seat cap
// (Unlimited when the plan bills per seat without a local cap).
func (s *Service) Seats(ctx context.Context, workspaceID string) (used, seatCap int64, err error) {
	seatCap = s.Resolve(ctx, workspaceID).SeatCap
	used, err = s.db.MemberCount(ctx, workspaceID)
	return used, seatCap, err
}

// CanInvite reports whether one more member fits under the plan's seat
// cap. It is the only remaining quota check in the product, used by the
// invitation and (future) SCIM paths.
//
// Fails open: a billing data problem must never block someone joining a
// workspace (§5.2). The lookup error is logged loudly so monitoring picks
// it up, but the invitation proceeds.
func (s *Service) CanInvite(ctx context.Context, workspaceID string) error {
	used, seatCap, err := s.Seats(ctx, workspaceID)
	if err != nil {
		slog.Error("seat check failed, allowing invite (fail open)",
			"error", err, "workspace_id", workspaceID)
		return nil
	}
	if seatCap != Unlimited && used >= seatCap {
		return connect.NewError(connect.CodeResourceExhausted, &SeatLimitError{
			Plan: s.Resolve(ctx, workspaceID).Name,
			Cap:  seatCap,
		})
	}
	return nil
}
