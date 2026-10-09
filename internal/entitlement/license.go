package entitlement

// Licenses verify offline against a compiled-in Ed25519 public key, so activation works air-gapped.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kata/licx"

	"github.com/nokku-sh/nokku/internal/db"
)

const (
	licenseApp    = "NOKKU"
	licenseEnv    = "NOKKU_LICENSE_KEY"
	licenseReload = 5 * time.Minute
	// A renewal reminder starts this long before the key expires.
	licenseWarnDays = 30
)

var (
	ErrLicenseInvalid     = errors.New("license key is not valid")
	ErrLicenseExpired     = errors.New("license key has expired")
	ErrLicenseShorter     = errors.New("the active license is valid for longer than this key")
	ErrLicenseUnsupported = errors.New("this build cannot verify license keys")
	ErrNotSelfHosted      = errors.New("licenses apply to self-hosted instances only")
)

// EnvLicense logs and ignores a rejected key, it never stops the core from starting.
func EnvLicense() *licx.Claims {
	key := os.Getenv(licenseEnv)
	if key == "" {
		return nil
	}
	claims, err := parseLicense(key)
	if err != nil {
		slog.Error(licenseEnv+" rejected, running without it", "error", err)
		return nil
	}
	return claims
}

// parseLicense keeps expired keys, they still carry the retention hold.
func parseLicense(key string) (*licx.Claims, error) {
	claims, err := licx.Verify(key, licenseApp)
	if err != nil && !errors.Is(err, licx.ErrExpired) {
		return nil, err
	}
	if claims.Plan != PlanEnterprise {
		return nil, fmt.Errorf("unknown license plan %q", claims.Plan)
	}
	return claims, nil
}

// License is nil without one. It may be expired, check IsExpired.
func (s *Service) License() *licx.Claims {
	return s.license.Load()
}

// ActivateLicense refuses a key that would shorten the active license, so an old key cannot undo a renewal.
func (s *Service) ActivateLicense(ctx context.Context, key string) error {
	if s.saas {
		return ErrNotSelfHosted
	}
	if !licx.HasPublicKey() {
		return ErrLicenseUnsupported
	}
	key = strings.TrimSpace(key)
	claims, err := parseLicense(key)
	if err != nil {
		return ErrLicenseInvalid
	}
	if claims.IsExpired() {
		return ErrLicenseExpired
	}
	if current := s.license.Load(); current != nil && validUntil(claims) < validUntil(current) {
		return ErrLicenseShorter
	}

	if err := s.conn.SysTx(ctx, func(q *db.Queries) error {
		return q.SetInstanceLicense(ctx, key)
	}); err != nil {
		return err
	}
	s.license.Store(claims)
	reportLicense(claims)
	return nil
}

// WatchLicense picks up a key activated in the UI, also from another replica, and repeats the expiry reminder.
func (s *Service) WatchLicense(ctx context.Context) {
	if !licx.HasPublicKey() {
		return
	}
	s.reloadLicense(ctx)
	reportLicense(s.license.Load())

	go func() {
		reported := time.Now()
		tick := time.Tick(licenseReload)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick:
			}
			before := s.license.Load()
			s.reloadLicense(ctx)
			after := s.license.Load()
			if after != before || time.Since(reported) >= 24*time.Hour {
				reportLicense(after)
				reported = time.Now()
			}
		}
	}()
}

// reloadLicense keeps the current license when the database is unreachable.
func (s *Service) reloadLicense(ctx context.Context) {
	var key string
	err := s.conn.SysTx(ctx, func(q *db.Queries) (err error) {
		key, err = q.GetInstanceLicense(ctx)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return
	}
	if err != nil {
		slog.Warn("license lookup failed", "error", err)
		return
	}
	stored, err := parseLicense(key)
	if err != nil {
		slog.Warn("stored license key rejected", "error", err)
		return
	}
	if current := s.license.Load(); current == nil || validUntil(stored) > validUntil(current) {
		s.license.Store(stored)
	}
}

func validUntil(c *licx.Claims) int64 {
	if c.ExpiresAt == 0 {
		return math.MaxInt64 // perpetual
	}
	return c.ExpiresAt
}

func reportLicense(c *licx.Claims) {
	if c == nil {
		return
	}
	if c.ExpiresAt == 0 {
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
