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
	"github.com/nokku-sh/nokku/internal/meta"
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

	stats, err := s.cfg.Conn.Q.GetWorkspaceStats(ctx, req.GetWorkspaceId())
	if err != nil {
		return nil, ErrInternal
	}

	// Pull the latest state from the provider (self-heals missed webhooks).
	if s.cfg.Billing != nil {
		s.cfg.Billing.Sync(ctx, req.GetWorkspaceId())
	}

	billingEnabled := s.cfg.Billing != nil
	resp := &nokkuv1.GetBillingResponse{
		BillingEnabled: &billingEnabled,
		Counts: &nokkuv1.WorkspaceCounts{
			Members:         &stats.MemberCount,
			Teams:           &stats.TeamCount,
			ServiceAccounts: &stats.ServiceAccountCount,
			Daemons:         &stats.DaemonCount,
			Targets:         &stats.TargetCount,
			Cas:             &stats.CaCount,
		},
		Metadata: planMetadata(s.cfg.Entitlements.Resolve(ctx, req.GetWorkspaceId())),
	}

	if sub, err := s.cfg.Conn.Q.GetSubscription(ctx, req.GetWorkspaceId()); err == nil {
		resp.CustomerId = &sub.CustomerID
		resp.ProductId = &sub.Plan
		resp.ProductName = new(planName(sub.Plan))
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
	if s.cfg.Billing == nil {
		return nil, ErrBillingDisabled
	}
	userID := meta.UserIDFromContext(ctx)
	if userID == "" {
		return nil, ErrUnauthorized
	}

	user, err := s.cfg.Conn.Q.GetUserByID(ctx, userID)
	if err != nil {
		return nil, ErrInternal
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
	if s.cfg.Billing == nil {
		return nil, ErrBillingDisabled
	}
	url, err := s.cfg.Billing.Portal(ctx, req.GetWorkspaceId())
	if err != nil {
		slog.Error("failed to create customer portal", "error", err)
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
	if s.cfg.Billing == nil {
		return nil, ErrBillingDisabled
	}
	if err := s.cfg.Billing.Cancel(
		ctx,
		req.GetWorkspaceId(),
		req.GetImmediate(),
		req.GetReason(),
	); err != nil {
		slog.Error("failed to cancel subscription", "error", err)
		return nil, ErrInternal
	}
	return &nokkuv1.CancelSubscriptionResponse{}, nil
}

// planName maps a plan key to the display name shown in the UI.
func planName(plan string) string {
	switch plan {
	case entitlement.PlanFlex:
		return "Nokku - Flex"
	case entitlement.PlanEnterprise:
		return "Nokku - Enterprise"
	default:
		return "Nokku - Community"
	}
}

// planMetadata exposes the resolved plan's quotas to the UI:
// credit_<resource> = included quota, max_<resource> = cap, -1 = unlimited.
func planMetadata(p entitlement.Plan) map[string]string {
	out := make(map[string]string, len(p.Limits)+len(p.Values))
	for r, q := range p.Limits {
		key := string(r)
		if q.Soft > 0 {
			out["credit_"+key] = strconv.FormatInt(q.Soft, 10)
		}
		if q.Hard >= 0 {
			out["max_"+key] = strconv.FormatInt(q.Hard, 10)
		}
	}
	for k, v := range p.Values {
		out[k] = strconv.FormatInt(v, 10)
	}
	return out
}
