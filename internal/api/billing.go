package api

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
)

type BillingService struct {
	cfg *config.Config
}

func NewBillingService(cfg *config.Config) *BillingService {
	return &BillingService{cfg: cfg}
}

func (s *BillingService) GetBilling(
	ctx context.Context,
	req *nokkuv1.GetBillingRequest,
) (*nokkuv1.GetBillingResponse, error) {
	if req.GetWorkspaceId() == "" {
		return nil, NewError(connect.CodeInvalidArgument, "Workspace ID is required")
	}

	var stats *db.GetWorkspaceStatsRow
	var sub *db.WorkspaceSubscription
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		stats, err = q.GetWorkspaceStats(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}
		// NotFound is fine: community workspaces have no subscription row.
		sub, _ = q.GetSubscription(ctx, req.GetWorkspaceId())
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	billingEnabled := s.cfg.Billing.Enabled()
	resp := &nokkuv1.GetBillingResponse{
		BillingEnabled: &billingEnabled,
		Counts: &nokkuv1.WorkspaceCounts{
			Members:         &stats.MemberCount,
			Teams:           &stats.TeamCount,
			ServiceAccounts: &stats.ServiceAccountCount,
			Targets:         &stats.TargetCount,
			Cas:             &stats.CaCount,
		},
		Metadata: planMetadata(
			s.cfg.Entitlements.Resolve(ctx, req.GetWorkspaceId()),
			s.cfg.Entitlements.Mode(),
		),
	}

	if sub != nil {
		resp.CustomerId = &sub.CustomerID
		resp.ProductId = &sub.Plan
		// Resolved plan name, not the raw row's plan string.
		resp.ProductName = new(s.cfg.Entitlements.Resolve(ctx, req.GetWorkspaceId()).Name)
		resp.Status = &sub.Status
		resp.CancelAtPeriodEnd = &sub.CancelAtPeriodEnd
		resp.CurrentPeriodEnd = db.SafeTimestamp(sub.CurrentPeriodEnd)
	}

	return resp, nil
}

func (s *BillingService) CreateCheckout(
	ctx context.Context,
	req *nokkuv1.CreateCheckoutRequest,
) (*nokkuv1.CreateCheckoutResponse, error) {
	if !s.cfg.Billing.Enabled() {
		return nil, ErrBillingDisabled
	}
	if err := s.requireWorkspaceOwner(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	user, err := s.cfg.IAM.GetUser(ctx, iam.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	url, err := s.cfg.Billing.Checkout(ctx, req.GetWorkspaceId(), user.Email)
	if errors.Is(err, billing.ErrActiveSubscription) {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"This workspace already has an active subscription. Manage it in the billing portal.",
		)
	}
	if err != nil {
		slog.Error("failed to create checkout", "error", err)
		return nil, ErrInternal
	}
	return &nokkuv1.CreateCheckoutResponse{
		Url: &url,
	}, nil
}

func (s *BillingService) CreatePortal(
	ctx context.Context,
	req *nokkuv1.CreatePortalRequest,
) (*nokkuv1.CreatePortalResponse, error) {
	if !s.cfg.Billing.Enabled() {
		return nil, ErrBillingDisabled
	}
	if err := s.requireWorkspaceOwner(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	url, err := s.cfg.Billing.Portal(ctx, req.GetWorkspaceId())
	if err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.CreatePortalResponse{
		Url: &url,
	}, nil
}

func (s *BillingService) CancelSubscription(
	ctx context.Context,
	req *nokkuv1.CancelSubscriptionRequest,
) (*nokkuv1.CancelSubscriptionResponse, error) {
	if !s.cfg.Billing.Enabled() {
		return nil, ErrBillingDisabled
	}
	if err := s.requireWorkspaceOwner(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	if err := s.cfg.Billing.Cancel(
		ctx,
		req.GetWorkspaceId(),
		req.GetImmediate(),
		req.GetReason(),
	); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.CancelSubscriptionResponse{}, nil
}

func (s *BillingService) requireWorkspaceOwner(ctx context.Context, workspaceID string) error {
	var ownerID string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		ownerID, err = q.GetWorkspaceOwner(ctx, workspaceID)
		return err
	}); err != nil {
		return DBError(err)
	}
	if ownerID != iam.UserIDFromContext(ctx) {
		return connect.NewError(
			connect.CodePermissionDenied,
			errors.New("workspace owner required"),
		)
	}
	return nil
}

// planMetadata is the stable frontend capability contract: plan,
// billing_mode, one boolean per feature flag, the seat cap under the
// legacy limit.members keys, and retention as a numeric value. Paid
// dimensions are exactly seats, retention, and features — nothing else.
func planMetadata(p entitlement.Plan, mode entitlement.Mode) map[string]string {
	out := make(map[string]string, len(p.Features)+5)
	out["plan"] = p.Name
	out["billing_mode"] = string(mode)
	for feature, enabled := range p.Features {
		out["feature."+feature] = strconv.FormatBool(enabled)
	}
	// limit.members keeps the pre-split UI contract for the seat cap.
	out["limit.members.included"] = strconv.FormatInt(p.SeatCap, 10)
	out["limit.members.hard"] = strconv.FormatInt(p.SeatCap, 10)
	out["seats.cap"] = strconv.FormatInt(p.SeatCap, 10)
	out["audit_log_retention_days"] = strconv.FormatInt(p.RetentionDays, 10)
	// Recording storage cap: plan value on SaaS, Unlimited on self-hosted.
	out["recordings_storage_cap"] = strconv.FormatInt(p.RecordingStorageBytes, 10)
	return out
}
