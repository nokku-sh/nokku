package api

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
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

	// Pull the latest state from the provider (self-heals missed webhooks)
	if s.cfg.Billing != nil {
		s.cfg.Billing.Sync(ctx, req.GetWorkspaceId())
	}

	resp := &nokkuv1.GetBillingResponse{
		Counts: &nokkuv1.WorkspaceCounts{
			Members:         &stats.MemberCount,
			Teams:           &stats.TeamCount,
			ServiceAccounts: &stats.ServiceAccountCount,
			Daemons:         &stats.DaemonCount,
			Targets:         &stats.TargetCount,
			Cas:             &stats.CaCount,
		},
	}

	sub, err := s.cfg.Conn.Q.GetSubscription(ctx, req.GetWorkspaceId())
	if err == nil {
		resp.CustomerId = &sub.CustomerID
		resp.ProductId = &sub.ProductID
		resp.ProductName = &sub.ProductName
		resp.Status = &sub.Status
		resp.CancelAtPeriodEnd = &sub.CancelAtPeriodEnd
		resp.CurrentPeriodEnd = db.SafeTimestamp(sub.CurrentPeriodEnd)

		if sub.Metadata != nil {
			resp.Metadata = stringifyMetadata(sub.Metadata)
		}
	}

	return resp, nil
}

func stringifyMetadata(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func (s *BillingService) CreateCheckout(
	ctx context.Context,
	req *nokkuv1.CreateCheckoutRequest,
) (*nokkuv1.CreateCheckoutResponse, error) {
	if s.cfg.Billing == nil {
		return nil, ErrBillingDisabled
	}
	url, err := s.cfg.Billing.Checkout(ctx, req.GetWorkspaceId())
	if err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.CreateCheckoutResponse{
		Url: &url,
	}, nil
}

func (s *BillingService) CreateCustomerPortal(
	ctx context.Context,
	req *nokkuv1.CreateCustomerPortalRequest,
) (*nokkuv1.CreateCustomerPortalResponse, error) {
	if s.cfg.Billing == nil {
		return nil, ErrBillingDisabled
	}
	url, err := s.cfg.Billing.Portal(ctx, req.GetWorkspaceId())
	if err != nil {
		slog.Error("failed to create customer portal", "err", err)
		return nil, ErrInternal
	}
	return &nokkuv1.CreateCustomerPortalResponse{
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
		slog.Error("failed to cancel subscription", "err", err)
		return nil, ErrInternal
	}
	return &nokkuv1.CancelSubscriptionResponse{}, nil
}
