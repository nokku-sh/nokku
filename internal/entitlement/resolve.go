package entitlement

import (
	"context"
	"errors"
	"log/slog"
)

// Mode distinguishes who operates the instance. Self-hosted and SaaS run
// the same binary and the same catalog; only the plan source differs.
type Mode string

const (
	ModeSelfHosted Mode = "self_hosted"
	ModeSaaS       Mode = "saas"
)

// Status is the provider-agnostic subscription state stored in
// workspace_subscriptions.status.
type Status string

const (
	StatusActive   Status = "active"
	StatusTrialing Status = "trialing"
	StatusPastDue  Status = "past_due"
	StatusInactive Status = "inactive"
)

// ActiveStatuses are the string values for SQL WHERE ... IN clauses.
var ActiveStatuses = []string{
	string(StatusActive),
	string(StatusTrialing),
	string(StatusPastDue),
}

// GrantsAccess is true only for active, trialing and past_due (grace
// period). Unknown or corrupted statuses fail closed.
func (s Status) GrantsAccess() bool {
	switch s {
	case StatusActive, StatusTrialing, StatusPastDue:
		return true
	case StatusInactive:
		return false
	}
	return false
}

// License is the instance license view entitlement needs. billing.Key
// implements it: license verification stays in billing (vendor side), plan
// resolution reads only its result.
type License interface {
	Valid() bool
	LicensedPlan() string
}

// Service resolves workspace plans. It is safe for concurrent use.
type Service struct {
	db      DB
	license License
	mode    Mode
}

// DB is the storage surface entitlement needs, kept narrow for tests.
type DB interface {
	// Subscription returns the workspace subscription row, or an error
	// when none exists (community workspaces).
	Subscription(ctx context.Context, workspaceID string) (plan string, status Status, err error)
	// MemberCount returns the current number of workspace members.
	MemberCount(ctx context.Context, workspaceID string) (int64, error)
}

func NewService(db DB, license License, mode Mode) *Service {
	if mode == "" {
		mode = ModeSelfHosted
	}
	return &Service{db: db, license: license, mode: mode}
}

func (s *Service) Mode() Mode {
	return s.mode
}

// Resolve returns the effective plan for a workspace, cached per request.
// Never returns a zero Plan: the worst case is Community.
//
// Order of precedence:
//  1. Self-hosted instance with a valid license: the licensed plan
//     (unknown names resolve to Enterprise for backward compatibility
//     with v1 keys, which carried no plan).
//  2. An active subscription row (SaaS, or self-hosted without license).
//  3. Community default.
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
	if s.mode == ModeSelfHosted && s.license != nil && s.license.Valid() {
		return resolvePlan(licensedPlanName(s.license))
	}

	plan := PlanCommunity
	subPlan, status, err := s.db.Subscription(ctx, workspaceID)
	switch {
	case err == nil && status.GrantsAccess():
		plan = subPlan
	case errors.Is(err, ErrNoSubscription):
		// No subscription row is the normal community case.
	case err == nil:
		// Inactive subscription falls back to Community.
	default:
		// Fail closed to Community so a billing outage never grants paid
		// features.
		slog.Warn("entitlement subscription lookup failed", "error", err, "workspace_id", workspaceID)
	}

	resolved := resolvePlan(plan)
	if s.mode == ModeSelfHosted {
		// Recording storage caps protect SaaS infrastructure only. On
		// self-hosted the disk is the customer's own, whatever the plan.
		resolved.RecordingStorageBytes = Unlimited
	}
	return resolved
}

// LicensedPlanFor reports the plan a valid license grants, defaulting to
// Enterprise for v1 keys that carried no plan name. Shared by resolve and
// the license API so both show the same truth.
func LicensedPlanFor(license License) string {
	if license == nil || !license.Valid() {
		return PlanCommunity
	}
	return licensedPlanName(license)
}

func licensedPlanName(license License) string {
	name := license.LicensedPlan()
	if _, ok := catalog[name]; !ok {
		return PlanEnterprise
	}
	return name
}

// Has reports whether a feature flag is enabled for the workspace.
func (s *Service) Has(ctx context.Context, workspaceID, feature string) bool {
	return s.Resolve(ctx, workspaceID).Has(feature)
}

// RetentionDays returns how long audit logs and session recordings are
// kept for the workspace.
func (s *Service) RetentionDays(ctx context.Context, workspaceID string) int64 {
	return s.Resolve(ctx, workspaceID).RetentionDays
}

// RecordingStorageBytes returns the workspace's session recording storage
// cap, Unlimited on self-hosted instances whatever the plan. It protects
// SaaS infrastructure, not the customer experience: retention is the
// plan-level storage knob.
func (s *Service) RecordingStorageBytes(ctx context.Context, workspaceID string) int64 {
	return s.Resolve(ctx, workspaceID).RecordingStorageBytes
}

// requestCache holds per-request plan resolutions so a single request
// (guard interceptor, handler, metadata rendering) triggers one Resolve.
type requestCache struct {
	plans map[string]Plan
}

type requestCacheKey struct{}

// WithRequestCache pins a plan cache onto the request context. The guard
// interceptor calls this; handlers downstream hit the cache.
func WithRequestCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestCacheKey{}, &requestCache{
		plans: make(map[string]Plan),
	})
}

func cacheFromContext(ctx context.Context) *requestCache {
	cache, _ := ctx.Value(requestCacheKey{}).(*requestCache)
	return cache
}
