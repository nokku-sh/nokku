package entitlement

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"
)

// ResourceCapError is the user-facing denial when a workspace's pooled
// resource budget is exhausted.
type ResourceCapError struct {
	Plan string
	Cap  int64
}

func (e *ResourceCapError) Error() string {
	return fmt.Sprintf(
		"your plan includes %d managed resources; delete some or upgrade to add more",
		e.Cap,
	)
}

// CheckResources reports whether one more managed resource (target, team,
// service account, CA, daemon, workspace domain) fits under the plan's
// pooled ResourceCap. It is the quota counterpart to CanInvite: seats are
// the per-seat-billed dimension with bespoke denial semantics and stay in
// CanInvite; everything else funnels through here.
//
// Like seats, this fails open (§5.2): a count lookup error never blocks
// daily work. The error is logged loudly so monitoring picks it up.
//
// Count-then-create can overshoot the cap by a few under concurrency. That
// is accepted: the cap exists to stop unbounded resource floods, not to
// invoice exactly, and seats have the same property. Exact enforcement
// would need per-workspace serialization and is not worth the latency.
//
// Delete and update paths are never gated: a workspace must always be able
// to delete its way out from under a cap, the same way a downgrade must
// never destroy data.
func (s *Service) CheckResources(ctx context.Context, workspaceID string) error {
	plan := s.Resolve(ctx, workspaceID)
	if plan.ResourceCap == Unlimited {
		return nil
	}
	used, err := s.db.ResourceCount(ctx, workspaceID)
	if err != nil {
		slog.Error("resource count failed, allowing create (fail open)",
			"error", err, "workspace_id", workspaceID)
		return nil
	}
	if used >= plan.ResourceCap {
		// Machine-readable quota metadata mirrors the feature paywall in
		// guard.go so the UI can render an upgrade affordance instead of a
		// raw error.
		err := connect.NewError(connect.CodeResourceExhausted, &ResourceCapError{
			Plan: plan.Name,
			Cap:  plan.ResourceCap,
		})
		err.Meta().Set("x-nokku-plan", plan.Name)
		err.Meta().Set("x-nokku-quota", "resources")
		err.Meta().Set("x-nokku-limit", strconv.FormatInt(plan.ResourceCap, 10))
		err.Meta().Set("x-nokku-upgrade", UpgradeURL)
		return err
	}
	return nil
}
