package api

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

type billingService struct {
	cfg *config.Config
}

func newBillingService(cfg *config.Config) *billingService {
	return &billingService{cfg: cfg}
}

func (s *billingService) GetBilling(
	ctx context.Context,
	req *nokkuv1.GetBillingRequest,
) (*nokkuv1.GetBillingResponse, error) {
	if req.GetWorkspaceId() == "" {
		return nil, newError(connect.CodeInvalidArgument, "Workspace ID is required")
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
		// Community workspaces have no subscription row.
		sub, _ = q.GetSubscription(ctx, req.GetWorkspaceId())
		return nil
	}); err != nil {
		return nil, err
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

func (s *billingService) CreateCheckout(
	ctx context.Context,
	req *nokkuv1.CreateCheckoutRequest,
) (*nokkuv1.CreateCheckoutResponse, error) {
	if !s.cfg.Billing.Enabled() {
		return nil, errBillingDisabled
	}
	if err := s.requireWorkspaceOwner(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	user, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, err
	}

	url, err := s.cfg.Billing.Checkout(ctx, req.GetWorkspaceId(), user.Email)
	if errors.Is(err, billing.ErrActiveSubscription) {
		return nil, newError(
			connect.CodeFailedPrecondition,
			"This workspace already has an active subscription. Manage it in the billing portal.",
		)
	}
	if err != nil {
		slog.Error("failed to create checkout", "error", err)
		return nil, errInternal
	}
	return &nokkuv1.CreateCheckoutResponse{
		Url: &url,
	}, nil
}

func (s *billingService) CreatePortal(
	ctx context.Context,
	req *nokkuv1.CreatePortalRequest,
) (*nokkuv1.CreatePortalResponse, error) {
	if !s.cfg.Billing.Enabled() {
		return nil, errBillingDisabled
	}
	if err := s.requireWorkspaceOwner(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	url, err := s.cfg.Billing.Portal(ctx, req.GetWorkspaceId())
	if err != nil {
		return nil, errInternal
	}
	return &nokkuv1.CreatePortalResponse{
		Url: &url,
	}, nil
}

func (s *billingService) CancelSubscription(
	ctx context.Context,
	req *nokkuv1.CancelSubscriptionRequest,
) (*nokkuv1.CancelSubscriptionResponse, error) {
	if !s.cfg.Billing.Enabled() {
		return nil, errBillingDisabled
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
		return nil, errInternal
	}
	return &nokkuv1.CancelSubscriptionResponse{}, nil
}

// GetLicense keeps reporting an expired license with its expiry, so the UI
// can ask for the renewal instead of showing a plain Community instance.
func (s *billingService) GetLicense(
	_ context.Context,
	_ *nokkuv1.GetLicenseRequest,
) (*nokkuv1.GetLicenseResponse, error) {
	license := s.cfg.Entitlements.License()
	active := s.cfg.Entitlements.Mode() == entitlement.ModeSelfHosted &&
		license != nil && !license.IsExpired()
	plan := entitlement.PlanCommunity
	if active {
		plan = license.Plan
	}
	var expiry *time.Time
	if license != nil && license.ExpiresAt != 0 {
		expiry = new(time.Unix(license.ExpiresAt, 0))
	}
	return &nokkuv1.GetLicenseResponse{
		Plan:      new(plan),
		Active:    new(active),
		ExpiresAt: db.SafeTimestamp(expiry),
	}, nil
}

func (s *billingService) ActivateLicense(
	ctx context.Context,
	req *nokkuv1.ActivateLicenseRequest,
) (*nokkuv1.ActivateLicenseResponse, error) {
	err := s.cfg.Entitlements.ActivateLicense(ctx, req.GetKey())
	switch {
	case errors.Is(err, entitlement.ErrLicenseInvalid):
		return nil, newError(connect.CodeInvalidArgument,
			"This license key is not valid. Paste it exactly as it came in the email.")
	case errors.Is(err, entitlement.ErrLicenseExpired):
		return nil, newError(connect.CodeInvalidArgument,
			"This license key has already expired. Use the key from your latest renewal email.")
	case errors.Is(err, entitlement.ErrLicenseShorter):
		return nil, newError(connect.CodeFailedPrecondition,
			"The active license is valid for longer than this key.")
	case errors.Is(err, entitlement.ErrNotSelfHosted),
		errors.Is(err, entitlement.ErrLicenseUnsupported):
		return nil, newError(connect.CodeFailedPrecondition, err.Error())
	case err != nil:
		slog.Error("failed to activate license", "error", err)
		return nil, errInternal
	}
	return &nokkuv1.ActivateLicenseResponse{}, nil
}

func (s *billingService) requireWorkspaceOwner(ctx context.Context, workspaceID string) error {
	err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return checkWorkspaceOwner(ctx, q, workspaceID)
	})
	if errors.Is(err, errPermissionDenied) {
		return connect.NewError(
			connect.CodePermissionDenied,
			errors.New("workspace owner required"),
		)
	}
	return err
}

// featuresProto returns the whole catalog so clients can render locked features.
func featuresProto(p entitlement.Plan) map[string]bool {
	features := make(map[string]bool, len(entitlement.CatalogFeatures))
	for _, feature := range entitlement.CatalogFeatures {
		features[feature.Code] = p.Has(feature.Code)
	}
	return features
}

// quotasProto uses -1 for unlimited.
func quotasProto(p entitlement.Plan) *nokkuv1.Quotas {
	return &nokkuv1.Quotas{
		Seats:                 new(p.SeatCap),
		RetentionDays:         new(p.RetentionDays),
		RecordingStorageBytes: new(p.RecordingStorageBytes),
		ResourceCap:           new(p.ResourceCap),
	}
}
