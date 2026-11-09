package entitlement

// Licenses verify against a compiled-in Ed25519 key, so air-gapped works.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"time"

	"github.com/mizuchilabs/inkan/license"

	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	licenseApp      = "NOKKU"
	licenseWarnDays = 30
	// Trades a held key for the current one. Only the key is sent.
	licenseRefreshURL = "https://license.nokku.sh/refresh"
	renewEvery        = 24 * time.Hour
	// The worker answers from memory for 30 seconds, asking more often gets nothing new.
	refreshGap     = 30 * time.Second
	refreshEntries = 10_000
	// A page and the daily pass wait for the worker, one that hangs must not hold them up.
	refreshWait = 3 * time.Second
)

var (
	ErrLicenseInvalid     = errors.New("license key is not valid")
	ErrLicenseExpired     = errors.New("license key has expired")
	ErrLicenseShorter     = errors.New("the active license is valid for longer than this key")
	ErrLicenseUnsupported = errors.New("this build cannot verify license keys")
	ErrLicenseInUse       = errors.New("this license is active in another workspace")
)

type licenseConfig struct {
	Key     string `env:"NOKKU_LICENSE_KEY"`
	Offline bool   `env:"NOKKU_LICENSE_OFFLINE"`
}

// UseEnvKey stores NOKKU_LICENSE_KEY for the self-hosted workspace, a rejected key never stops the start.
func (s *Service) UseEnvKey(ctx context.Context, workspaceID string) {
	if s.envKey == "" {
		return
	}
	claims, err := s.verifyLicense(s.envKey)
	if err == nil {
		err = s.storeLicense(ctx, workspaceID, s.envKey, claims)
	}
	switch {
	case err == nil:
		reportLicense(claims)
	case !errors.Is(err, ErrLicenseShorter):
		slog.Error("NOKKU_LICENSE_KEY rejected, running without it", "error", err)
	}
}

func (s *Service) ActivateLicense(ctx context.Context, workspaceID, key string) error {
	claims, err := s.verifyLicense(key)
	switch {
	case errors.Is(err, license.ErrNoPublicKey):
		return ErrLicenseUnsupported
	case err != nil:
		return ErrLicenseInvalid
	case claims.IsExpired():
		return ErrLicenseExpired
	case s.saas && claims.ID == "":
		// The unique license id is what stops one key from unlocking many workspaces.
		return ErrLicenseInvalid
	}
	if err := s.storeLicense(ctx, workspaceID, key, claims); err != nil {
		return err
	}
	if !s.saas {
		reportLicense(claims)
	}
	return nil
}

// RefreshLicense picks up seats bought a moment ago, at most once per refreshGap.
func (s *Service) RefreshLicense(ctx context.Context, workspaceID string) error {
	if s.offline || !s.refreshed.SetNX(workspaceID, struct{}{}) {
		return nil
	}
	st, err := s.Status(ctx, workspaceID)
	if err != nil || st.Row == nil || OnTrial(st.Row) {
		return err
	}
	return s.refresh(ctx, workspaceID, st.Row.Key)
}

// renewLoop picks up renewals and seat changes, self-hosted it also warns of a coming expiry.
func (s *Service) renewLoop(ctx context.Context) {
	tick := time.Tick(renewEvery)
	for {
		s.renewAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

func (s *Service) renewAll(ctx context.Context) {
	rows, err := s.conn.Sys().ListLicenses(ctx)
	if err != nil {
		slog.Warn("listing license keys failed", "error", err)
		return
	}
	for _, row := range rows {
		if !s.offline {
			if err := s.refresh(ctx, row.WorkspaceID, row.Key); err != nil {
				slog.Warn("license refresh failed", "error", err, "workspace_id", row.WorkspaceID)
			}
		}
		if s.saas {
			continue
		}
		st, err := s.Status(ctx, row.WorkspaceID)
		if err == nil && st.License == nil {
			slog.Warn("stored license key rejected, running on the Community limits")
		}
		reportLicense(st.License)
	}
}

func (s *Service) refresh(ctx context.Context, workspaceID, key string) error {
	ask, cancel := context.WithTimeout(ctx, refreshWait)
	fresh, err := license.Refresh(ask, licenseRefreshURL, key, licenseApp, s.publicKey)
	cancel()
	if err != nil || fresh == license.Clean(key) {
		return err
	}
	claims, err := s.verifyLicense(fresh)
	if err != nil {
		return err
	}
	if err := s.storeLicense(ctx, workspaceID, fresh, claims); err != nil && !errors.Is(err, ErrLicenseShorter) {
		return err
	}
	return nil
}

// storeLicense refuses a shorter key, so an old one cannot undo a renewal.
func (s *Service) storeLicense(ctx context.Context, workspaceID, key string, claims *license.Claims) error {
	held, err := s.Status(ctx, workspaceID)
	if err != nil {
		return err
	}
	if held.License != nil && validUntil(claims) < validUntil(held.License) {
		return ErrLicenseShorter
	}

	var licenseID *string
	if claims.ID != "" {
		licenseID = new(claims.ID)
	}
	var endsAt *time.Time
	if claims.ExpiresAt != 0 {
		endsAt = new(time.Unix(claims.ExpiresAt, 0).UTC())
	}
	err = s.conn.Sys().SetLicense(ctx, &db.SetLicenseParams{
		WorkspaceID: workspaceID,
		Key:         license.Clean(key),
		LicenseID:   licenseID,
		EndsAt:      endsAt,
	})
	if db.IsUniqueViolation(err) {
		return ErrLicenseInUse
	}
	return err
}

// verifyLicense keeps expired keys, they still carry the retention hold.
func (s *Service) verifyLicense(key string) (*license.Claims, error) {
	claims, err := license.Verify(key, licenseApp, s.publicKey, "")
	if err != nil && !errors.Is(err, license.ErrExpired) {
		return nil, err
	}
	if claims.Plan != PlanPro && claims.Plan != PlanEnterprise {
		return nil, fmt.Errorf("unknown license plan %q", claims.Plan)
	}
	// inkan signs the bought quantity into every key, Enterprise has no seat cap.
	if claims.Plan != PlanPro {
		return claims, nil
	}
	seats, err := licenseSeats(claims)
	switch {
	case err != nil:
		return nil, err
	case seats == 0:
		return nil, errors.New("a Pro license must name its seats")
	}
	return claims, nil
}

func licenseSeats(c *license.Claims) (int64, error) {
	raw, ok := c.Meta["seats"]
	if !ok {
		return 0, nil
	}
	seats, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seats <= 0 {
		return 0, fmt.Errorf("license seats %q are no count", raw)
	}
	return seats, nil
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
			"data_kept_until", HoldEnd(expires))
	case left < licenseWarnDays*24*time.Hour:
		slog.Warn("license expires soon, activate the renewed key under Billing",
			"expires_at", expires, "days_left", int(math.Ceil(left.Hours()/24)))
	default:
	}
}
