package entitlement

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/db"
)

type resourceCapError struct {
	Plan string
	Cap  int64
}

func (e *resourceCapError) Error() string {
	return fmt.Sprintf(
		"your plan includes %d managed resources; delete some or upgrade to add more",
		e.Cap,
	)
}

// CheckResources reports whether one more managed resource fits under the
// plan's pooled ResourceCap.
func (s *Service) CheckResources(ctx context.Context, workspaceID string) error {
	plan := s.Resolve(ctx, workspaceID)
	if plan.ResourceCap == unlimited {
		return nil
	}

	var used int64
	if err := s.conn.SysTx(ctx, func(q *db.Queries) (err error) {
		used, err = q.CountWorkspaceResources(ctx, workspaceID)
		return err
	}); err != nil {
		slog.Error("resource count failed, allowing create",
			"error", err, "workspace_id", workspaceID)
		return nil
	}

	if used >= plan.ResourceCap {
		// Same metadata as the feature paywall so the UI can prompt an upgrade.
		err := connect.NewError(connect.CodeResourceExhausted, &resourceCapError{
			Plan: plan.Name,
			Cap:  plan.ResourceCap,
		})
		err.Meta().Set("x-nokku-plan", plan.Name)
		err.Meta().Set("x-nokku-quota", "resources")
		err.Meta().Set("x-nokku-limit", strconv.FormatInt(plan.ResourceCap, 10))
		err.Meta().Set("x-nokku-upgrade", upgradeURL)
		return err
	}
	return nil
}
