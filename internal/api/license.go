package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type LicenseService struct {
	cfg *config.Config
}

func NewLicenseService(cfg *config.Config) *LicenseService {
	return &LicenseService{cfg: cfg}
}

func (s *LicenseService) GetLicense(
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
