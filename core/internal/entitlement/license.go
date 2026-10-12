package entitlement

// Licenses verify offline against a compiled-in Ed25519 public key, so activation works air-gapped.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/inkan/license"
)

const (
	licenseApp = "NOKKU"
	// A renewal reminder starts this long before the key expires.
	licenseWarnDays = 30
	// The license worker trades a held key for the current one. The key is all that is sent.
	licenseRefreshURL = "https://license.nokku.sh/refresh"
)

var (
	ErrLicenseInvalid     = errors.New("license key is not valid")
	ErrLicenseExpired     = errors.New("license key has expired")
	ErrLicenseShorter     = errors.New("the active license is valid for longer than this key")
	ErrLicenseUnsupported = errors.New("this build cannot verify license keys")
	ErrNotSelfHosted      = errors.New("licenses apply to self-hosted instances only")
)

type licenseConfig struct {
	Key     string `env:"NOKKU_LICENSE_KEY"`
	Offline bool   `env:"NOKKU_LICENSE_OFFLINE"`
}

// loadLicense takes the key from the environment and the one activated in the UI, then keeps the held one renewed.
func (s *Service) loadLicense(ctx context.Context) error {
	cfg, err := env.ParseAs[licenseConfig]()
	if err != nil {
		return err
	}
	if cfg.Key != "" {
		// A rejected key never stops the core from starting.
		if err := s.takeLicense(cfg.Key); err != nil {
			slog.Error("NOKKU_LICENSE_KEY rejected, running without it", "error", err)
		}
	}

	stored, err := s.conn.Sys().GetInstanceLicense(ctx)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return fmt.Errorf("loading license: %w", err)
	default:
		if err := s.takeLicense(stored); err != nil && !errors.Is(err, ErrLicenseShorter) {
			slog.Warn("stored license key rejected", "error", err)
		}
	}

	// A server without a key never asks.
	if !cfg.Offline {
		go s.license.Renew(ctx, licenseRefreshURL,
			func(key string) {
				if err := s.storeLicense(ctx, key); err != nil {
					slog.Warn("renewed license key not stored", "error", err)
				}
			},
			func(err error) { slog.Warn("license refresh failed", "error", err) },
		)
	}
	go s.remindLicense(ctx)
	return nil
}

// verifyLicense keeps expired keys, they still carry the retention hold.
func (s *Service) verifyLicense(key string) (*license.Claims, error) {
	claims, err := license.Verify(key, licenseApp, s.publicKey, "")
	if err != nil && !errors.Is(err, license.ErrExpired) {
		return nil, err
	}
	if claims.Plan != PlanEnterprise {
		return nil, fmt.Errorf("unknown license plan %q", claims.Plan)
	}
	return claims, nil
}

// takeLicense refuses a key that would shorten the held license, so an old key cannot undo a renewal.
func (s *Service) takeLicense(key string) error {
	claims, err := s.verifyLicense(key)
	if err != nil {
		return err
	}
	if s.shorterLicense(claims) {
		return ErrLicenseShorter
	}
	_, _ = s.license.Set(key)
	return nil
}

func (s *Service) shorterLicense(claims *license.Claims) bool {
	held := s.License()
	return held != nil && validUntil(claims) < validUntil(held)
}

// License is nil without one. It may be expired, check IsExpired.
func (s *Service) License() *license.Claims {
	claims, _ := s.license.Claims()
	return claims
}

func (s *Service) ActivateLicense(ctx context.Context, key string) error {
	if s.saas {
		return ErrNotSelfHosted
	}
	claims, err := s.verifyLicense(key)
	switch {
	case errors.Is(err, license.ErrNoPublicKey):
		return ErrLicenseUnsupported
	case err != nil:
		return ErrLicenseInvalid
	case claims.IsExpired():
		return ErrLicenseExpired
	case s.shorterLicense(claims):
		return ErrLicenseShorter
	}

	if err := s.storeLicense(ctx, license.Clean(key)); err != nil {
		return err
	}
	_, _ = s.license.Set(key)
	reportLicense(claims)
	return nil
}

func (s *Service) storeLicense(ctx context.Context, key string) error {
	return s.conn.Sys().SetInstanceLicense(ctx, key)
}

// remindLicense repeats the expiry warning once a day, a server can run for longer than its key lasts.
func (s *Service) remindLicense(ctx context.Context) {
	reportLicense(s.License())
	tick := time.Tick(24 * time.Hour)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			reportLicense(s.License())
		}
	}
}

func validUntil(c *license.Claims) int64 {
	if c.ExpiresAt == 0 {
		return math.MaxInt64 // perpetual
	}
	return c.ExpiresAt
}

func reportLicense(c *license.Claims) {
	if c == nil || c.ExpiresAt == 0 {
		return
	}
	expires := time.Unix(c.ExpiresAt, 0).UTC()
	switch left := time.Until(expires); {
	case left <= 0:
		slog.Error("license expired, licensed features are off until a new key is activated",
			"expired_at", expires,
			"data_kept_until", expires.AddDate(0, 0, holdDays))
	case left < licenseWarnDays*24*time.Hour:
		slog.Warn("license expires soon, activate the renewed key under Billing",
			"expires_at", expires, "days_left", int(math.Ceil(left.Hours()/24)))
	default:
	}
}
