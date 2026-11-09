package api

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/mizuchilabs/inkan/license"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

type billingService struct {
	cfg *config.Config
}

func (s *billingService) GetBilling(
	ctx context.Context,
	_ *nokkuv1.GetBillingRequest,
) (*nokkuv1.GetBillingResponse, error) {
	ws := actor.WorkspaceIDFromContext(ctx)
	// Seats bought in the portal count once the owner is back on this page.
	if err := s.cfg.Entitlements.RefreshLicense(ctx, ws); err != nil {
		slog.Warn("license refresh failed", "error", err, "workspace_id", ws)
	}
	var userCount int64
	var resourceCount int64
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		userCount, err = q.CountActiveUsers(ctx, ws)
		if err != nil {
			return err
		}
		resourceCount, err = q.CountWorkspaceResources(ctx, ws)
		return err
	}); err != nil {
		return nil, err
	}

	st, err := s.cfg.Entitlements.Status(ctx, ws)
	if err != nil {
		slog.Warn("entitlement license lookup failed", "error", err, "workspace_id", ws)
	}
	plan := st.Plan
	resp := &nokkuv1.GetBillingResponse{
		Plan:          new(plan.Name),
		Mode:          new(s.cfg.Mode()),
		Features:      featuresProto(plan),
		Quotas:        quotasProto(plan),
		UserCount:     new(userCount),
		ResourceCount: new(resourceCount),
		License:       licenseProto(st.License),
	}
	if st.HeldUntil != nil {
		resp.HeldQuotas, resp.HeldUntil = quotasProto(st.Keep), db.SafeTimestamp(st.HeldUntil)
	}
	// Only the hosted service has trials and deletes a workspace.
	if row := st.Row; row != nil && s.cfg.SaaS {
		if entitlement.OnTrial(row) {
			resp.TrialEndsAt = db.SafeTimestamp(row.EndsAt)
		}
		resp.DeleteAt = db.SafeTimestamp(deletionDate(row))
	}
	return resp, nil
}

// GetLicense still reports an expired license, so the UI can ask to renew.
func (s *billingService) GetLicense(
	ctx context.Context,
	_ *nokkuv1.GetLicenseRequest,
) (*nokkuv1.GetLicenseResponse, error) {
	st, err := s.cfg.Entitlements.Status(ctx, actor.WorkspaceIDFromContext(ctx))
	if err != nil {
		return nil, err
	}
	return licenseProto(st.License), nil
}

// licenseProto is Community unless the key is active, an expired one still names its end.
func licenseProto(c *license.Claims) *nokkuv1.GetLicenseResponse {
	active := c != nil && !c.IsExpired()
	plan := entitlement.PlanCommunity
	if active {
		plan = c.Plan
	}
	var expiry *time.Time
	if c != nil && c.ExpiresAt != 0 {
		expiry = new(time.Unix(c.ExpiresAt, 0))
	}
	return &nokkuv1.GetLicenseResponse{
		Plan:      new(plan),
		Active:    new(active),
		ExpiresAt: db.SafeTimestamp(expiry),
	}
}

func (s *billingService) ActivateLicense(
	ctx context.Context,
	req *nokkuv1.ActivateLicenseRequest,
) (*nokkuv1.ActivateLicenseResponse, error) {
	err := s.cfg.Entitlements.ActivateLicense(ctx, actor.WorkspaceIDFromContext(ctx), req.GetKey())
	switch {
	case errors.Is(err, entitlement.ErrLicenseInvalid):
		return nil, connect.NewError(connect.CodeInvalidArgument,
			"This license key is not valid. Paste it exactly as it came in the email.")
	case errors.Is(err, entitlement.ErrLicenseExpired):
		return nil, connect.NewError(connect.CodeInvalidArgument,
			"This license key has already expired. Use the key from your latest renewal email.")
	case errors.Is(err, entitlement.ErrLicenseShorter):
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			"The active license is valid for longer than this key.")
	case errors.Is(err, entitlement.ErrLicenseInUse):
		return nil, connect.NewError(connect.CodeAlreadyExists,
			"This license is already active in another workspace.")
	case errors.Is(err, entitlement.ErrLicenseUnsupported):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err.Error())
	case err != nil:
		return nil, err
	}
	return &nokkuv1.ActivateLicenseResponse{}, nil
}

// featuresProto returns the whole catalog so clients can show locked features.
func featuresProto(p entitlement.Plan) map[string]bool {
	features := make(map[string]bool, len(entitlement.CatalogFeatures))
	for _, feature := range entitlement.CatalogFeatures {
		features[feature.Code] = p.Has(feature.Code)
	}
	return features
}

func catalogProto() []*nokkuv1.PlanFeature {
	out := make([]*nokkuv1.PlanFeature, len(entitlement.CatalogFeatures))
	for i, f := range entitlement.CatalogFeatures {
		out[i] = &nokkuv1.PlanFeature{Key: new(f.Code), Label: new(f.Label), Plan: new(f.Plan)}
	}
	return out
}

// quotasProto uses -1 for unlimited.
func quotasProto(p entitlement.Plan) *nokkuv1.Quotas {
	return &nokkuv1.Quotas{
		Seats:                  new(p.SeatCap),
		AuditRetentionDays:     new(p.AuditRetentionDays),
		RecordingRetentionDays: new(p.RecordingRetentionDays),
		RecordingStorageBytes:  new(p.RecordingStorageBytes),
		ResourceCap:            new(p.ResourceCap),
	}
}
