package entitlement

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/inkan/license"

	"github.com/nokku-sh/nokku/internal/db"
)

// holdDays keeps the data limits of an ended plan in force, so a lapsed card never deletes data right away.
const holdDays = 30

type Service struct {
	conn *db.Connection
	// saas only changes where the plan comes from.
	saas bool
	// publicKey verifies license keys. A build without one takes no key.
	publicKey string
	license   *license.Keeper // self-hosted only, the held key may be expired
}

// New loads the license of a self-hosted server. With saas the plan comes from the subscription instead.
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

// Resolve never returns a zero Plan. A lookup that fails gives Community, so a billing outage never grants paid features.
func (s *Service) Resolve(ctx context.Context, workspaceID string) Plan {
	plan, _, err := s.lookup(ctx, workspaceID)
	if err != nil {
		slog.Warn("entitlement subscription lookup failed", "error", err, "workspace_id", workspaceID)
	}
	return plan
}

// lookup returns the plan in force and the one whose data limits the purge jobs honor. They differ during the hold.
func (s *Service) lookup(ctx context.Context, workspaceID string) (plan, keep Plan, err error) {
	if s.saas {
		sub, subErr := s.conn.Sys().GetSubscription(ctx, workspaceID)
		return fromSubscription(sub, subErr)
	}
	plan, keep = fromLicense(s.License())
	// These caps protect SaaS infrastructure only, licensed plans included.
	plan.RecordingStorageBytes, plan.ResourceCap = unlimited, unlimited
	keep.RecordingStorageBytes, keep.ResourceCap = unlimited, unlimited
	return plan, keep, nil
}

// fromSubscription takes what GetSubscription answered. A row that cannot be read is Community next to the error.
func fromSubscription(sub *db.WorkspaceSubscription, err error) (plan, keep Plan, _ error) {
	free := resolvePlan(PlanCommunity)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return free, free, nil
	case err != nil:
		return free, free, err
	case Active(sub.Status):
		plan = resolvePlan(sub.Plan)
		if sub.Seats > 0 {
			plan.SeatCap = sub.Seats
		}
		return plan, plan, nil
	case sub.EndedAt != nil && inHold(*sub.EndedAt):
		return free, resolvePlan(sub.Plan), nil
	}
	return free, free, nil
}

// fromLicense takes the held key, nil without one.
func fromLicense(c *license.Claims) (plan, keep Plan) {
	free := resolvePlan(PlanCommunity)
	switch {
	case c == nil:
		return free, free
	case !c.IsExpired():
		plan = resolvePlan(c.Plan)
		return plan, plan
	case inHold(time.Unix(c.ExpiresAt, 0)):
		return free, resolvePlan(c.Plan)
	}
	return free, free
}

// Active reports whether a subscription in this Stripe status pays for its plan. past_due is a grace period, an unknown status fails closed.
func Active(status string) bool {
	switch status {
	case "active", "trialing", "past_due":
		return true
	}
	return false
}

func inHold(endedAt time.Time) bool {
	return time.Since(endedAt) < holdDays*24*time.Hour
}

func (s *Service) Has(ctx context.Context, workspaceID, feature string) bool {
	return s.Resolve(ctx, workspaceID).Has(feature)
}

// RetentionDays honors the hold and errors instead of falling back, so a failed lookup never shortens what is kept.
func (s *Service) RetentionDays(ctx context.Context, workspaceID string) (int64, error) {
	_, keep, err := s.lookup(ctx, workspaceID)
	return keep.RetentionDays, err
}

func (s *Service) RecordingStorageBytes(ctx context.Context, workspaceID string) (int64, error) {
	_, keep, err := s.lookup(ctx, workspaceID)
	return keep.RecordingStorageBytes, err
}
