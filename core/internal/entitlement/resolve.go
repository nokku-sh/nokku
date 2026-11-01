package entitlement

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/inkan/license"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// holdDays keeps an ended plan's limits, a lapsed card deletes nothing at once.
const holdDays = 30

// A trial row's current_period_end is when the trial ends.
const (
	SourceTrial  = "trial"
	SourceStripe = "stripe"
)

type Service struct {
	conn *db.Connection
	saas bool
	// publicKey verifies license keys. A build without one takes no key.
	publicKey string
	license   *license.Keeper
}

// Status is what a workspace may do now, and the limits purge jobs honor.
type Status struct {
	Plan Plan
	// Keep differs from Plan during the hold, which ends at HeldUntil.
	Keep      Plan
	HeldUntil *time.Time
	Sub       *db.WorkspaceSubscription // hosted only, nil without a row
}

func New(ctx context.Context, conn *db.Connection, publicKey string, saas bool) (*Service, error) {
	s := newService(conn, publicKey, saas)
	if saas {
		return s, nil
	}
	return s, s.loadLicense(ctx)
}

func newService(conn *db.Connection, publicKey string, saas bool) *Service {
	return &Service{
		conn:      conn,
		saas:      saas,
		publicKey: publicKey,
		license:   license.NewKeeper(licenseApp, publicKey, ""),
	}
}

// Resolve gives Community on an outage: no paid features, signing carries on.
func (s *Service) Resolve(ctx context.Context, workspaceID string) Plan {
	st, err := s.Status(ctx, workspaceID)
	if err != nil {
		slog.Warn("entitlement subscription lookup failed", "error", err, "workspace_id", workspaceID)
	}
	return st.Plan
}

// Status falls back to Community next to the error, like Resolve.
func (s *Service) Status(ctx context.Context, workspaceID string) (Status, error) {
	if s.saas {
		return fromSubscription(s.conn.Sys().GetSubscription(ctx, workspaceID))
	}
	st := fromLicense(s.License())
	// These caps protect SaaS infrastructure only, licensed plans included.
	st.Plan.RecordingStorageBytes, st.Plan.ResourceCap = unlimited, unlimited
	st.Keep.RecordingStorageBytes, st.Keep.ResourceCap = unlimited, unlimited
	return st, nil
}

func fromSubscription(sub *db.WorkspaceSubscription, err error) (Status, error) {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Status{Plan: inactive, Keep: inactive}, nil
	case err != nil:
		free := resolvePlan(PlanCommunity)
		return Status{Plan: free, Keep: free}, err
	case running(sub):
		plan := resolvePlan(sub.Plan)
		if sub.Seats > 0 {
			plan.SeatCap = sub.Seats
		}
		return Status{Plan: plan, Keep: plan, Sub: sub}, nil
	}
	st := after(inactive, resolvePlan(sub.Plan), Ended(sub))
	st.Sub = sub
	return st, nil
}

func running(sub *db.WorkspaceSubscription) bool {
	if sub.Source == SourceTrial {
		return sub.CurrentPeriodEnd != nil && time.Now().Before(*sub.CurrentPeriodEnd)
	}
	return Active(sub.Status)
}

// Ended is when sub stopped paying, nil while it runs or if it never paid.
func Ended(sub *db.WorkspaceSubscription) *time.Time {
	switch {
	case running(sub):
		return nil
	case sub.Source == SourceTrial:
		return sub.CurrentPeriodEnd
	}
	return sub.EndedAt
}

func fromLicense(c *license.Claims) Status {
	free := resolvePlan(PlanCommunity)
	switch {
	case c == nil:
		return Status{Plan: free, Keep: free}
	case !c.IsExpired():
		plan := resolvePlan(c.Plan)
		if seats, _ := licenseSeats(c); seats > 0 {
			plan.SeatCap = seats
		}
		return Status{Plan: plan, Keep: plan}
	}
	return after(free, resolvePlan(c.Plan), new(time.Unix(c.ExpiresAt, 0)))
}

// after puts next in force and holds ended's data limits for holdDays.
func after(next, ended Plan, endedAt *time.Time) Status {
	if endedAt == nil || !time.Now().Before(HoldEnd(*endedAt)) {
		return Status{Plan: next, Keep: next}
	}
	return Status{Plan: next, Keep: ended, HeldUntil: new(HoldEnd(*endedAt))}
}

// Active takes past_due as a grace period, an unknown status fails closed.
func Active(status string) bool {
	switch status {
	case "active", "trialing", "past_due":
		return true
	}
	return false
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
