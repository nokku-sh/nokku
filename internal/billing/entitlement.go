package billing

import (
	"context"
	"errors"
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

const (
	FeatureOIDC             = "oidc"
	FeatureEnforceSSO       = "enforce_sso"
	FeatureSAML             = "saml"
	FeatureAuditExport      = "audit_export"
	FeatureExternalKMS      = "external_kms"
	ValueAuditRetentionDays = "audit_log_retention_days"
)

type Mode string

const (
	ModeSelfHosted Mode = "self_hosted"
	ModeSaaS       Mode = "saas"
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

// Quota for one resource: Soft is included in the base price (overage starts
// above it), Hard is the enforced cap (-1 = unlimited).
type Quota struct {
	Soft int64 `json:"soft"`
	Hard int64 `json:"hard"`
}

type Plan struct {
	Name     string
	Features map[string]bool
	Limits   map[Resource]Quota
	Values   map[string]int64
}

// catalog defines plans in code so enforcement limits never drift. Soft
// quotas must match the Stripe price tiers. Hard quotas are enforced locally.
var catalog = map[string]Plan{
	PlanCommunity: {
		Features: map[string]bool{
			FeatureOIDC: true,
		},
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
			FeatureOIDC:        true,
			FeatureEnforceSSO:  true,
			FeatureSAML:        true,
			FeatureAuditExport: true,
		},
		Limits: map[Resource]Quota{
			// Metered resources: soft = included, hard = unlimited (billed).
			ResourceMembers: {Soft: 10, Hard: -1},
			// Keep the same finite cap so service accounts cannot bypass member
			// pricing. They are not metered separately.
			ResourceServiceAccounts: {Soft: 10, Hard: 10},
			ResourceTargets:         {Soft: 50, Hard: -1},
			// Not metered: enforced caps.
			ResourceTeams: {Soft: 500, Hard: 500},
			ResourceCas:   {Soft: 100, Hard: 100},
		},
		Values: map[string]int64{
			ValueAuditRetentionDays: 90,
		},
	},
	PlanEnterprise: {
		Features: map[string]bool{
			FeatureOIDC:        true,
			FeatureEnforceSSO:  true,
			FeatureSAML:        true,
			FeatureAuditExport: true,
			FeatureExternalKMS: true,
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

// licenseState reports whether the instance is licensed (on-premise). When
// active, every workspace resolves to Enterprise.
type licenseState interface {
	Valid() bool
}

type PolicyService struct {
	db      *db.Connection
	license licenseState
	mode    Mode
}

func NewPolicyService(db *db.Connection, lc licenseState, modes ...Mode) *PolicyService {
	mode := ModeSelfHosted
	if len(modes) > 0 {
		mode = modes[0]
	}
	return &PolicyService{db: db, license: lc, mode: mode}
}

func (s *PolicyService) Mode() Mode {
	return s.mode
}

// Resolve returns the effective plan for a workspace. An active instance
// license overrides subscriptions only in self-hosted mode.
func (s *PolicyService) Resolve(ctx context.Context, workspaceID string) Plan {
	if s.mode == ModeSelfHosted && s.license != nil && s.license.Valid() {
		return resolvePlan(PlanEnterprise)
	}
	var sub *db.WorkspaceSubscription
	if err := s.db.WithTx(ctx, func(q *db.Queries) (err error) {
		sub, err = q.GetSubscription(ctx, workspaceID)
		return err
	}); err != nil {
		return resolvePlan(PlanCommunity)
	}

	if sub == nil || !Status(sub.Status).GrantsAccess() {
		return resolvePlan(PlanCommunity)
	}
	return resolvePlan(sub.Plan)
}

// Check returns ResourceExhausted if creating one more of r would exceed the
// hard cap. Fails open on DB errors.
func (s *PolicyService) Check(ctx context.Context, workspaceID string, r Resource) error {
	plan := s.Resolve(ctx, workspaceID)
	quota, ok := plan.Limits[r]
	if !ok || quota.Hard < 0 {
		return nil
	}
	var stats *db.GetWorkspaceStatsRow
	if err := s.db.WithTx(ctx, func(q *db.Queries) (err error) {
		stats, err = q.GetWorkspaceStats(ctx, workspaceID)
		return err
	}); err != nil {
		slog.Warn(
			"entitlement stats lookup failed",
			"error", err,
			"workspace_id", workspaceID,
		)
		return connect.NewError(connect.CodeUnavailable, errors.New("quota check unavailable"))
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
func (s *PolicyService) Has(ctx context.Context, workspaceID, feature string) bool {
	return s.Resolve(ctx, workspaceID).Features[feature]
}

// Int returns a numeric plan value (e.g. retention days) or fallback.
func (s *PolicyService) Int(ctx context.Context, workspaceID, key string, fallback int64) int64 {
	if v, ok := s.Resolve(ctx, workspaceID).Values[key]; ok {
		return v
	}
	return fallback
}

func resolvePlan(name string) Plan {
	base, ok := catalog[name]
	if !ok {
		if name != "" {
			slog.Debug("unknown plan, using community", "plan", name)
		}
		base = catalog[PlanCommunity]
		name = PlanCommunity
	}
	return Plan{
		Name:     name,
		Features: maps.Clone(base.Features),
		Limits:   maps.Clone(base.Limits),
		Values:   maps.Clone(base.Values),
	}
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
