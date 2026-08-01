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
	plan := entitlement.PlanCommunity
	if s.cfg.License.Valid() {
		plan = entitlement.PlanEnterprise
	}

	return &nokkuv1.GetLicenseResponse{
		Plan:      new(plan),
		Active:    new(s.cfg.License.Valid()),
		Key:       new(s.cfg.License.Key),
		ExpiresAt: db.SafeTimestamp(s.cfg.License.ExpiresAt),
	}, nil
}
