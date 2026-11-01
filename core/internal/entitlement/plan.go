// Package entitlement alone enforces plans. Quotas fail open, features closed.
package entitlement

import "slices"

const (
	FeatureEnforceSSO     = "enforce_sso"
	FeatureSCIM           = "scim"
	FeatureAuditExport    = "audit_export"
	FeatureExpiringAccess = "expiring_access"
	FeatureAccessReview   = "access_review"
	FeatureIdleTimeout    = "idle_timeout"
	FeatureAccessRequests = "access_requests"
	FeatureAuditStreaming = "audit_streaming"
)

const (
	PlanCommunity  = "community"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
	// PlanInactive is a lapsed hosted workspace. Hosted has no free plan.
	PlanInactive = "inactive"
)

const TrialDays = 30

const unlimited int64 = -1

// CatalogFeatures is the one list of what a plan has, the console reads it too.
var CatalogFeatures = []Feature{
	{FeatureEnforceSSO, "Enforced single sign-on", PlanPro},
	{FeatureAuditExport, "Audit log export", PlanPro},
	{FeatureExpiringAccess, "Expiring access", PlanPro},
	{FeatureAccessReview, "Access review report", PlanPro},
	{FeatureIdleTimeout, "Idle session timeout", PlanPro},
	{FeatureSCIM, "SCIM provisioning", PlanEnterprise},
	{FeatureAccessRequests, "Access requests", PlanEnterprise},
	{FeatureAuditStreaming, "Audit log streaming", PlanEnterprise},
}

var PlanNames = map[string]string{
	PlanCommunity:  "Community",
	PlanPro:        "Pro",
	PlanEnterprise: "Enterprise",
	PlanInactive:   "inactive",
}

// plans go from the smallest to the largest, Has depends on the order.
var plans = []Plan{
	{
		Name:                   PlanCommunity,
		SeatCap:                5,
		ResourceCap:            50,
		AuditRetentionDays:     30,
		RecordingRetentionDays: 7,
		RecordingStorageBytes:  1 << 30,
	},
	{
		Name:                   PlanPro,
		SeatCap:                unlimited,
		ResourceCap:            2000,
		AuditRetentionDays:     90,
		RecordingRetentionDays: 90,
		RecordingStorageBytes:  50 << 30,
	},
	{
		Name:                   PlanEnterprise,
		SeatCap:                unlimited,
		ResourceCap:            unlimited,
		AuditRetentionDays:     365,
		RecordingRetentionDays: 365,
		RecordingStorageBytes:  500 << 30,
	},
}

// inactive keeps Community's features and data limits, so the owner can SSO in
// to subscribe. It signs no user certificates and takes nothing new.
var inactive = func() Plan {
	p := resolvePlan(PlanCommunity)
	p.Name, p.SeatCap, p.ResourceCap = PlanInactive, 0, 0
	return p
}()

type Feature struct {
	Code  string
	Label string
	// Plan is the smallest plan with the feature, larger ones have it too.
	Plan string
}

type Plan struct {
	Name        string
	SeatCap     int64 // maximum members, unlimited means per-seat billing
	ResourceCap int64
	// Audit rows are small, recordings are what costs storage.
	AuditRetentionDays     int64
	RecordingRetentionDays int64
	// RecordingStorageBytes stops abuse, normal use hits the retention first.
	RecordingStorageBytes int64
}

func (p Plan) Has(feature string) bool {
	for _, f := range CatalogFeatures {
		if f.Code == feature {
			return planRank(p.Name) >= planRank(f.Plan)
		}
	}
	return false
}

// planRank is -1 for no plan, so a zero Plan has nothing.
func planRank(name string) int {
	if name == PlanInactive {
		name = PlanCommunity
	}
	return slices.IndexFunc(plans, func(p Plan) bool { return p.Name == name })
}

// resolvePlan reads an unknown name as Community.
func resolvePlan(name string) Plan {
	return plans[max(planRank(name), 0)]
}
