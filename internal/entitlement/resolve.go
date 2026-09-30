package entitlement

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

var ErrNoSubscription = pgx.ErrNoRows

// Mode only changes where the plan comes from.
type Mode string

const (
	ModeSelfHosted Mode = "self_hosted"
	ModeSaaS       Mode = "saas"
)

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

type Service struct {
	conn    txRunner
	license string
	mode    Mode
}

type txRunner interface {
	WithTx(ctx context.Context, fn func(*db.Queries) error) error
}

func NewService(conn txRunner, license string, mode Mode) *Service {
	if mode == "" {
		mode = ModeSelfHosted
	}
	return &Service{conn: conn, license: license, mode: mode}
}

func (s *Service) Mode() Mode {
	return s.mode
}

// Resolve is cached per request and never returns a zero Plan. A self-hosted
// license wins, then an active subscription, then Community.
func (s *Service) Resolve(ctx context.Context, workspaceID string) Plan {
	if cache := cacheFromContext(ctx); cache != nil {
		if plan, ok := cache.plans[workspaceID]; ok {
			return plan
		}
	}

	plan := s.resolve(ctx, workspaceID)

	if cache := cacheFromContext(ctx); cache != nil {
		cache.plans[workspaceID] = plan
	}
	return plan
}

func (s *Service) resolve(ctx context.Context, workspaceID string) Plan {
	plan := PlanCommunity
	if s.mode == ModeSelfHosted && s.license != "" {
		plan = s.license
	} else {
		var sub *db.WorkspaceSubscription
		err := s.conn.WithTx(ctx, func(q *db.Queries) (err error) {
			sub, err = q.GetSubscription(ctx, workspaceID)
			return err
		})

		switch {
		case err == nil && Status(sub.Status).grantsAccess():
			plan = sub.Plan
		case errors.Is(err, ErrNoSubscription), err == nil:
		default:
			// Fail closed so a billing outage never grants paid features.
			slog.Warn("entitlement subscription lookup failed", "error", err, "workspace_id", workspaceID)
		}
	}

	resolved := resolvePlan(plan)
	if s.mode == ModeSelfHosted {
		// These caps protect SaaS infrastructure only, licensed plans included.
		resolved.RecordingStorageBytes = unlimited
		resolved.ResourceCap = unlimited
	}
	return resolved
}

func (s *Service) Has(ctx context.Context, workspaceID, feature string) bool {
	return s.Resolve(ctx, workspaceID).Has(feature)
}

func (s *Service) RetentionDays(ctx context.Context, workspaceID string) int64 {
	return s.Resolve(ctx, workspaceID).RetentionDays
}

func (s *Service) RecordingStorageBytes(ctx context.Context, workspaceID string) int64 {
	return s.Resolve(ctx, workspaceID).RecordingStorageBytes
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
