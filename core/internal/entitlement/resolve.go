package entitlement

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/inkan/license"

	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// holdDays keeps an ended plan's limits, a lapsed license deletes nothing at once.
const holdDays = 30

type Service struct {
	conn *db.Connection
	saas bool
	// publicKey verifies license keys. A build without one takes no key.
	publicKey string
	envKey    string
	offline   bool
	refreshed *cache.TTL[string, struct{}]
}

// Status is what a workspace may do now, and the limits purge jobs honor.
type Status struct {
	Plan Plan
	// Keep differs from Plan during the hold, which ends at HeldUntil.
	Keep      Plan
	HeldUntil *time.Time
	// License is nil without a key that verifies. It may be expired.
	License *license.Claims
	Row     *db.WorkspaceLicense // nil without one
}

func New(ctx context.Context, conn *db.Connection, publicKey string, saas bool) (*Service, error) {
	cfg, err := env.ParseAs[licenseConfig]()
	if err != nil {
		return nil, err
	}
	s := newService(conn, publicKey, saas)
	s.envKey, s.offline = cfg.Key, cfg.Offline
	go s.renewLoop(ctx)
	return s, nil
}

func newService(conn *db.Connection, publicKey string, saas bool) *Service {
	return &Service{
		conn:      conn,
		saas:      saas,
		publicKey: publicKey,
		refreshed: cache.New[string, struct{}](refreshEntries, refreshGap),
	}
}

// Resolve gives Community on an outage: no paid features, signing carries on.
func (s *Service) Resolve(ctx context.Context, workspaceID string) Plan {
	st, err := s.Status(ctx, workspaceID)
	if err != nil {
		slog.Warn("entitlement license lookup failed", "error", err, "workspace_id", workspaceID)
	}
	return st.Plan
}

// Status falls back to Community next to the error, like Resolve.
func (s *Service) Status(ctx context.Context, workspaceID string) (Status, error) {
	row, err := s.conn.Sys().GetLicense(ctx, workspaceID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		row = nil
	case err != nil:
		// An outage hands out no paid feature and never stops signing.
		free := resolvePlan(PlanCommunity)
		return s.uncapped(Status{Plan: free, Keep: free}), err
	}
	return s.fromRow(row), nil
}

// fromRow reads no plan as inactive on the hosted service, as Community self-hosted.
func (s *Service) fromRow(row *db.WorkspaceLicense) Status {
	none := resolvePlan(PlanCommunity)
	if s.saas {
		none = inactive
	}
	var st Status
	switch {
	case row == nil:
		st = Status{Plan: none, Keep: none}
	case !OnTrial(row):
		st = s.fromKey(row.Key, none)
	case Ended(row) == nil:
		st = Status{Plan: trial, Keep: trial}
	default:
		st = after(none, trial, row.EndsAt)
	}
	st.Row = row
	return s.uncapped(st)
}

// uncapped lifts the caps that only protect SaaS infrastructure, on a self-hosted server.
func (s *Service) uncapped(st Status) Status {
	if !s.saas {
		st.Plan.RecordingStorageBytes, st.Plan.ResourceCap = unlimited, unlimited
		st.Keep.RecordingStorageBytes, st.Keep.ResourceCap = unlimited, unlimited
	}
	return st
}

// fromKey reads a key this build cannot verify as no plan, the daily renewal logs it.
func (s *Service) fromKey(key string, none Plan) Status {
	c, err := s.verifyLicense(key)
	if err != nil {
		return Status{Plan: none, Keep: none}
	}
	plan := resolvePlan(c.Plan)
	if c.Plan == PlanPro {
		plan.SeatCap, _ = licenseSeats(c)
	}
	st := Status{Plan: plan, Keep: plan}
	if c.IsExpired() {
		st = after(none, plan, new(time.Unix(c.ExpiresAt, 0)))
	}
	st.License = c
	return st
}

// after puts next in force and holds ended's data limits for holdDays.
func after(next, ended Plan, endedAt *time.Time) Status {
	if endedAt == nil || !time.Now().Before(HoldEnd(*endedAt)) {
		return Status{Plan: next, Keep: next}
	}
	return Status{Plan: next, Keep: ended, HeldUntil: new(HoldEnd(*endedAt))}
}

// OnTrial is a hosted workspace that has activated no key yet.
func OnTrial(row *db.WorkspaceLicense) bool {
	return row.Key == ""
}

// Ended is when the trial or key ran out, nil while it runs or for a key that never expires.
func Ended(row *db.WorkspaceLicense) *time.Time {
	if row.EndsAt == nil || time.Now().Before(*row.EndsAt) {
		return nil
	}
	return row.EndsAt
}

func HoldEnd(endedAt time.Time) time.Time {
	return endedAt.Add(holdDays * 24 * time.Hour)
}

// AuditRetentionDays errors, so a failed lookup never shortens what is kept.
func (s *Service) AuditRetentionDays(ctx context.Context, workspaceID string) (int64, error) {
	st, err := s.Status(ctx, workspaceID)
	return st.Keep.AuditRetentionDays, err
}

func (s *Service) RecordingRetentionDays(ctx context.Context, workspaceID string) (int64, error) {
	st, err := s.Status(ctx, workspaceID)
	return st.Keep.RecordingRetentionDays, err
}

func (s *Service) RecordingStorageBytes(ctx context.Context, workspaceID string) (int64, error) {
	st, err := s.Status(ctx, workspaceID)
	return st.Keep.RecordingStorageBytes, err
}
