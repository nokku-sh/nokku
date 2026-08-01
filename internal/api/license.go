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
	m := s.cfg.License

	resp := &nokkuv1.GetLicenseResponse{
		Plan:   new(entitlement.PlanCommunity),
		Status: new(string(entitlement.StatusInactive)),
	}
	if !m.Configured() {
		return resp, nil
	}

	if m.Active() {
		resp.Plan = new(entitlement.PlanEnterprise)
		resp.Status = new(string(entitlement.StatusActive))
	}
	resp.Source = new("license")
	resp.Key = new(m.Key())
	resp.ExpiresAt = db.SafeTimestamp(m.ExpiresAt())
	return resp, nil
}
