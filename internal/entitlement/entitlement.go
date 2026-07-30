// Package entitlement resolves plan limits, feature flags and values
// from local state only (in-code catalog + DB row per workspace).
package entitlement

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"

	"connectrpc.com/connect"
	"github.com/nokku-sh/nokku/internal/db"
)

type Resource string

const (
	ResourceMembers         Resource = "members"
	ResourceTeams           Resource = "teams"
	ResourceTargets         Resource = "targets"
	ResourceCas             Resource = "cas"
	ResourceServiceAccounts Resource = "service_accounts"
)

// Feature and value keys that appear in catalog plans and DB overrides.
const (
	FeatureEnforceSSO       = "enforce_sso"
	ValueAuditRetentionDays = "audit_log_retention_days"
)

// Plan names stored in workspace_subscriptions.plan.
const (
	PlanCommunity  = "community"
	PlanFlex       = "flex"
	PlanEnterprise = "enterprise"
)

// Status is the provider-agnostic subscription state stored locally.
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

// GrantsAccess is true for active, trialing and past_due (grace period).
func (s Status) GrantsAccess() bool { return s != StatusInactive }

// Quota for one resource: Soft is included in base price (overage
// starts above it), Hard is the enforcement cap (-1 = unlimited).
type Quota struct {
	Soft int64 `json:"soft"`
	Hard int64 `json:"hard"`
}

type Plan struct {
	Features map[string]bool
	Limits   map[Resource]Quota
	Values   map[string]int64
}

// Overrides customize a catalog plan. Stored as JSONB in
// workspace_subscriptions.overrides.
type Overrides struct {
	Features map[string]bool  `json:"features,omitempty"`
	Limits   map[string]Quota `json:"limits,omitempty"`
	Values   map[string]int64 `json:"values,omitempty"`
}

// catalog defines plans in code so enforcement limits never drift.
// soft limits are included in the base price, hard limits are enforced.
var catalog = map[string]Plan{
	PlanCommunity: {
		Features: map[string]bool{},
		Limits: map[Resource]Quota{
			ResourceMembers:         {Soft: 5, Hard: 5},
			ResourceServiceAccounts: {Soft: 2, Hard: 2},
			ResourceTargets:         {Soft: 10, Hard: 10},
			ResourceTeams:           {Soft: 3, Hard: 3},
			ResourceCas:             {Soft: 2, Hard: 2},
		},
		Values: map[string]int64{
			ValueAuditRetentionDays: 7,
		},
	},
	PlanFlex: {
		Features: map[string]bool{
			FeatureEnforceSSO: true,
		},
		Limits: map[Resource]Quota{
			ResourceMembers:         {Soft: 10, Hard: 5000},
			ResourceServiceAccounts: {Soft: 5, Hard: 5000},
			ResourceTargets:         {Soft: 50, Hard: 10000},
			ResourceTeams:           {Soft: 500, Hard: 500},
			ResourceCas:             {Soft: 100, Hard: 100},
		},
		Values: map[string]int64{
			ValueAuditRetentionDays: 90,
		},
	},
	PlanEnterprise: {
		Features: map[string]bool{
			FeatureEnforceSSO: true,
		},
		Limits: map[Resource]Quota{
			ResourceMembers:         {Soft: -1, Hard: -1},
			ResourceServiceAccounts: {Soft: -1, Hard: -1},
			ResourceTargets:         {Soft: -1, Hard: -1},
			ResourceTeams:           {Soft: -1, Hard: -1},
			ResourceCas:             {Soft: -1, Hard: -1},
		},
		Values: map[string]int64{
			ValueAuditRetentionDays: 365,
		},
	},
}

// QuotaError is returned by Check when a hard cap is reached.
type QuotaError struct {
	Resource Resource
	Limit    int64
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("%s limit (%d) reached for your current plan", e.Resource, e.Limit)
}

type Service struct {
	q *db.Queries
}

func New(q *db.Queries) *Service {
	return &Service{q: q}
}

// Resolve returns the effective plan for a workspace (falls back to Community).
func (s *Service) Resolve(ctx context.Context, workspaceID string) Plan {
	sub, err := s.q.GetSubscription(ctx, workspaceID)
	if err != nil || !Status(sub.Status).GrantsAccess() {
		return resolvePlan(PlanCommunity, nil)
	}
	return resolvePlan(sub.Plan, parseOverrides(sub.Overrides))
}

// Check returns ResourceExhausted if creating one more of r would
// exceed the hard cap. Fails open on DB errors.
func (s *Service) Check(ctx context.Context, workspaceID string, r Resource) error {
	plan := s.Resolve(ctx, workspaceID)
	quota, ok := plan.Limits[r]
	if !ok || quota.Hard < 0 {
		return nil
	}

	stats, err := s.q.GetWorkspaceStats(ctx, workspaceID)
	if err != nil {
		slog.Debug(
			"entitlement: stats lookup failed, allowing",
			"err", err,
			"workspace_id", workspaceID,
		)
		return nil
	}

	if currentCount(stats, r) >= quota.Hard {
		return connect.NewError(connect.CodeResourceExhausted, &QuotaError{
			Resource: r,
			Limit:    quota.Hard,
		})
	}
	return nil
}

// Has reports whether a feature flag is enabled for the workspace.
func (s *Service) Has(ctx context.Context, workspaceID, feature string) bool {
	return s.Resolve(ctx, workspaceID).Features[feature]
}

// Int returns a numeric plan value (e.g. retention days) or fallback.
func (s *Service) Int(ctx context.Context, workspaceID, key string, fallback int64) int64 {
	if v, ok := s.Resolve(ctx, workspaceID).Values[key]; ok {
		return v
	}
	return fallback
}

func resolvePlan(name string, ov *Overrides) Plan {
	base, ok := catalog[name]
	if !ok {
		if name != "" {
			slog.Debug("entitlement: unknown plan, using community", "plan", name)
		}
		base = catalog[PlanCommunity]
	}
	return base.apply(ov)
}

// apply returns a copy of p with overrides merged in.
func (p Plan) apply(ov *Overrides) Plan {
	if ov == nil {
		return p
	}
	out := Plan{
		Features: make(map[string]bool, len(p.Features)+len(ov.Features)),
		Limits:   make(map[Resource]Quota, len(p.Limits)+len(ov.Limits)),
		Values:   make(map[string]int64, len(p.Values)+len(ov.Values)),
	}
	maps.Copy(out.Features, p.Features)
	maps.Copy(out.Features, ov.Features)
	maps.Copy(out.Limits, p.Limits)
	for r, q := range ov.Limits {
		out.Limits[Resource(r)] = q
	}
	maps.Copy(out.Values, p.Values)
	maps.Copy(out.Values, ov.Values)
	return out
}

func parseOverrides(m map[string]any) *Overrides {
	if len(m) == 0 {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var ov Overrides
	if err := json.Unmarshal(raw, &ov); err != nil {
		slog.Debug("entitlement: ignoring malformed overrides", "err", err)
		return nil
	}
	return &ov
}

func currentCount(stats *db.GetWorkspaceStatsRow, r Resource) int64 {
	switch r {
	case ResourceMembers:
		return stats.MemberCount
	case ResourceServiceAccounts:
		return stats.ServiceAccountCount
	case ResourceTargets:
		return stats.TargetCount
	case ResourceTeams:
		return stats.TeamCount
	case ResourceCas:
		return stats.CaCount
	}
	return 0
}
