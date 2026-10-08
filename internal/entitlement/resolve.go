package entitlement

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kata/licx"

	"github.com/nokku-sh/nokku/internal/db"
)

var ErrNoSubscription = pgx.ErrNoRows

type Status string

const (
	StatusActive   Status = "active"
	StatusTrialing Status = "trialing"
	StatusPastDue  Status = "past_due"
	StatusInactive Status = "inactive"
)

var ActiveStatuses = []string{
	string(StatusActive),
	string(StatusTrialing),
	string(StatusPastDue),
}

// grantsAccess fails closed on unknown statuses. past_due is a grace period.
func (s Status) grantsAccess() bool {
	switch s {
	case StatusActive, StatusTrialing, StatusPastDue:
		return true
	case StatusInactive:
		return false
	}
	return false
}

// holdDays is how long the data limits of an ended plan stay in force, so a
// lapsed card or license never deletes data right away.
const holdDays = 30

type Service struct {
	conn txRunner
	// saas only changes where the plan comes from.
	saas    bool
	license atomic.Pointer[licx.Claims] // self-hosted only, may be expired
}

type txRunner interface {
	SysTx(ctx context.Context, fn func(*db.Queries) error) error
}

// NewService takes the license from the environment, see EnvLicense.
// WatchLicense adds a key activated in the UI. saas is the hosted service,
// where the plan comes from the subscription and a license counts for nothing.
func NewService(conn txRunner, license *licx.Claims, saas bool) *Service {
	s := &Service{conn: conn, saas: saas}
	s.license.Store(license)
	return s
}

// Resolve is cached per request and never returns a zero Plan. A self-hosted
// license wins, then an active subscription, then Community.
func (s *Service) Resolve(ctx context.Context, workspaceID string) Plan {
	if cache := cacheFromContext(ctx); cache != nil {
		if plan, ok := cache.plans[workspaceID]; ok {
			return plan
		}
	}

	plan, _, err := s.lookup(ctx, workspaceID)
	if err != nil {
		// Fail closed so a billing outage never grants paid features.
		slog.Warn("entitlement subscription lookup failed", "error", err, "workspace_id", workspaceID)
	}

	if cache := cacheFromContext(ctx); cache != nil {
		cache.plans[workspaceID] = plan
	}
	return plan
}

// lookup returns the plan in force and the plan whose data limits the purge
// jobs honor. They differ for holdDays after a paid plan ended. On a failed
// subscription read both are Community, next to the error.
func (s *Service) lookup(ctx context.Context, workspaceID string) (plan, keep Plan, err error) {
	name, held := PlanCommunity, ""
	var seats int64

	license := s.license.Load()
	if s.saas {
		license = nil
	}
	if license != nil && !license.IsExpired() {
		name = license.Plan
	} else {
		if license != nil && inHold(time.Unix(license.ExpiresAt, 0)) {
			held = license.Plan
		}
		var sub *db.WorkspaceSubscription
		subErr := s.conn.SysTx(ctx, func(q *db.Queries) (err error) {
			sub, err = q.GetSubscription(ctx, workspaceID)
			return err
		})
		switch {
		case errors.Is(subErr, ErrNoSubscription):
		case subErr != nil:
			err = subErr
		case Status(sub.Status).grantsAccess():
			name, seats = sub.Plan, sub.Seats
		case held == "" && sub.EndedAt != nil && inHold(*sub.EndedAt):
			held = sub.Plan
		}
	}

	plan = s.plan(name)
	if seats > 0 {
		plan.SeatCap = seats
	}
	keep = plan
	if held != "" {
		keep = s.plan(held)
	}
	return plan, keep, err
}

func (s *Service) plan(name string) Plan {
	plan := resolvePlan(name)
	if !s.saas {
		// These caps protect SaaS infrastructure only, licensed plans included.
		plan.RecordingStorageBytes = unlimited
		plan.ResourceCap = unlimited
	}
	return plan
}

func inHold(endedAt time.Time) bool {
	return time.Since(endedAt) < holdDays*24*time.Hour
}

func (s *Service) Has(ctx context.Context, workspaceID, feature string) bool {
	return s.Resolve(ctx, workspaceID).Has(feature)
}

// RetentionDays and RecordingStorageBytes are for the jobs that delete data.
// They honor the hold and error instead of falling back to Community, so
// neither a failed lookup nor a fresh downgrade shortens what gets deleted.
func (s *Service) RetentionDays(ctx context.Context, workspaceID string) (int64, error) {
	_, keep, err := s.lookup(ctx, workspaceID)
	return keep.RetentionDays, err
}

func (s *Service) RecordingStorageBytes(ctx context.Context, workspaceID string) (int64, error) {
	_, keep, err := s.lookup(ctx, workspaceID)
	return keep.RecordingStorageBytes, err
}

type requestCache struct {
	plans map[string]Plan
}

type requestCacheKey struct{}

func withRequestCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestCacheKey{}, &requestCache{
		plans: make(map[string]Plan),
	})
}

func cacheFromContext(ctx context.Context) *requestCache {
	cache, _ := ctx.Value(requestCacheKey{}).(*requestCache)
	return cache
}
