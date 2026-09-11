package entitlement

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/db"
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

// CheckResources reports whether one more managed resource fits under the
// plan's pooled ResourceCap.
func (s *Service) CheckResources(ctx context.Context, workspaceID string) error {
	plan := s.Resolve(ctx, workspaceID)
	if plan.ResourceCap == Unlimited {
		return nil
	}

	var used int64
	if err := s.conn.WithTx(ctx, func(q *db.Queries) (err error) {
		used, err = q.CountWorkspaceResources(ctx, workspaceID)
		return err
	}); err != nil {
		slog.Error("resource count failed, allowing create",
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
