package api

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/billing"
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
			s.cfg.Billing.Resolve(ctx, req.GetWorkspaceId()),
			s.cfg.Billing.Mode(),
		),
	}

	if sub != nil {
		resp.CustomerId = &sub.CustomerID
		resp.ProductId = &sub.Plan
		resp.ProductName = new(sub.Plan)
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
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, auth.UserIDFromContext(ctx))
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
	if ownerID != auth.UserIDFromContext(ctx) {
		return connect.NewError(
			connect.CodePermissionDenied,
			errors.New("workspace owner required"),
		)
	}
	return nil
}

// planMetadata is the stable frontend capability contract. The legacy
// credit_/max_ keys remain for older clients. New clients should use
// plan, billing_mode, feature.<name>, and limit.<resource>.<field>.
func planMetadata(p billing.Plan, mode billing.Mode) map[string]string {
	out := make(map[string]string, len(p.Limits)*4+len(p.Features)+len(p.Values)+2)
	out["plan"] = p.Name
	out["billing_mode"] = string(mode)
	for r, q := range p.Limits {
		key := string(r)
		out["limit."+key+".included"] = strconv.FormatInt(q.Soft, 10)
		out["limit."+key+".hard"] = strconv.FormatInt(q.Hard, 10)
		if q.Soft > 0 {
			out["credit_"+key] = strconv.FormatInt(q.Soft, 10)
		}
		if q.Hard >= 0 {
			out["max_"+key] = strconv.FormatInt(q.Hard, 10)
		}
	}
	for _, k := range []string{
		billing.FeatureOIDC,
		billing.FeatureEnforceSSO,
		billing.FeatureSAML,
		billing.FeatureAuditExport,
		billing.FeatureExternalKMS,
	} {
		out["feature."+k] = strconv.FormatBool(p.Features[k])
	}
	for k, v := range p.Values {
		out[k] = strconv.FormatInt(v, 10)
	}
	return out
}
