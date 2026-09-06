package api

import (
	"context"
	"errors"
	"log/slog"

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

	var memberCount int64
	var resourceCount int64
	var sub *db.WorkspaceSubscription
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		memberCount, err = q.CountWorkspaceSeats(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}
		resourceCount, err = q.CountWorkspaceResources(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}
		// NotFound is fine: community workspaces have no subscription row.
		sub, _ = q.GetSubscription(ctx, req.GetWorkspaceId())
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	plan := s.cfg.Entitlements.Resolve(ctx, req.GetWorkspaceId())
	resp := &nokkuv1.GetBillingResponse{
		Plan:          new(plan.Name),
		Mode:          new(string(s.cfg.Entitlements.Mode())),
		Features:      featuresProto(plan),
		Quotas:        quotasProto(plan),
		MemberCount:   new(memberCount),
		ResourceCount: new(resourceCount),
	}

	if sub != nil {
		resp.Subscription = &nokkuv1.Subscription{
			Status:            new(sub.Status),
			CancelAtPeriodEnd: new(sub.CancelAtPeriodEnd),
			CurrentPeriodEnd:  db.SafeTimestamp(sub.CurrentPeriodEnd),
		}
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
	user, err := s.cfg.IAM.GetUser(ctx)
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

func (s *BillingService) GetLicense(
	_ context.Context,
	_ *nokkuv1.GetLicenseRequest,
) (*nokkuv1.GetLicenseResponse, error) {
	license := s.cfg.Billing.License
	plan := entitlement.PlanCommunity
	active := s.cfg.Entitlements.Mode() == entitlement.ModeSelfHosted && license.Valid()
	if active {
		plan = entitlement.LicensedPlanFor(license)
	}

	return &nokkuv1.GetLicenseResponse{
		Plan:      new(plan),
		Active:    new(active),
		ExpiresAt: db.SafeTimestamp(license.ExpiresAt),
	}, nil
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

// featuresProto returns the full feature catalog with per-plan enablement,
// so clients can render locked features (not just enabled ones).
func featuresProto(p entitlement.Plan) map[string]bool {
	return map[string]bool{
		entitlement.FeatureOIDC:        p.Has(entitlement.FeatureOIDC),
		entitlement.FeatureEnforceSSO:  p.Has(entitlement.FeatureEnforceSSO),
		entitlement.FeatureSAML:        p.Has(entitlement.FeatureSAML),
		entitlement.FeatureAuditExport: p.Has(entitlement.FeatureAuditExport),
		entitlement.FeatureExternalKMS: p.Has(entitlement.FeatureExternalKMS),
		entitlement.FeatureSCIM:        p.Has(entitlement.FeatureSCIM),
	}
}

// quotasProto renders the plan's caps; -1 means unlimited.
func quotasProto(p entitlement.Plan) *nokkuv1.Quotas {
	return &nokkuv1.Quotas{
		Seats:                 new(p.SeatCap),
		RetentionDays:         new(p.RetentionDays),
		RecordingStorageBytes: new(p.RecordingStorageBytes),
		ResourceCap:           new(p.ResourceCap),
	}
}
