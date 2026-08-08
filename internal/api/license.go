package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
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
	plan := billing.PlanCommunity
	active := s.cfg.Billing.Mode() == billing.ModeSelfHosted && s.cfg.License.Valid()
	if active {
		plan = billing.PlanEnterprise
	}

	return &nokkuv1.GetLicenseResponse{
		Plan:      new(plan),
		Active:    new(active),
		ExpiresAt: db.SafeTimestamp(s.cfg.License.ExpiresAt),
	}, nil
}
