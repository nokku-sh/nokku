// Package entitlement is the only place plan logic is enforced. Quotas fail open, features fail closed.
package entitlement

import "slices"

const (
	FeatureOIDC           = "oidc"
	FeatureEnforceSSO     = "enforce_sso"
	FeatureSCIM           = "scim"
	FeatureAuditExport    = "audit_export"
	FeatureExpiringAccess = "expiring_access"
	FeatureAccessReview   = "access_review"
	FeatureIdleTimeout    = "idle_timeout"
	FeatureAccessRequests = "access_requests"
	FeatureAuditStreaming = "audit_streaming"
	FeatureLegalHold      = "legal_hold"
)

const (
	PlanCommunity  = "community"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
	// PlanInactive is a hosted workspace whose trial or subscription is over. Hosted has no free plan.
	PlanInactive = "inactive"
)

// TrialDays is how long a new hosted workspace runs on Pro before it needs a subscription.
const TrialDays = 30

type Feature struct {
	Code  string
	Label string
	// Plan is the smallest plan that has the feature, every larger one has it too.
	Plan string
}

var CatalogFeatures = []Feature{
	{FeatureOIDC, "OIDC single sign-on", PlanCommunity},
	{FeatureEnforceSSO, "enforced single sign-on", PlanPro},
	{FeatureAuditExport, "audit log export", PlanPro},
	{FeatureExpiringAccess, "expiring access", PlanPro},
	{FeatureAccessReview, "the access review report", PlanPro},
	{FeatureIdleTimeout, "the idle session timeout", PlanPro},
	{FeatureSCIM, "SCIM provisioning", PlanEnterprise},
	{FeatureAccessRequests, "access requests", PlanEnterprise},
	{FeatureAuditStreaming, "audit log streaming", PlanEnterprise},
	{FeatureLegalHold, "legal hold", PlanEnterprise},
}

const unlimited int64 = -1

type Plan struct {
	Name        string
	SeatCap     int64 // maximum members, unlimited means per-seat billing
	ResourceCap int64 // pooled cap on managed resources
	// Audit rows are small, recordings are what costs storage.
	AuditRetentionDays     int64
	RecordingRetentionDays int64
	// RecordingStorageBytes is a stop for abuse, sized so that normal use runs into the retention first.
	RecordingStorageBytes int64
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

// inactive keeps the free features and data limits of Community, so the owner can still sign in with SSO to
// subscribe. It signs no user certificates and takes nothing new.
var inactive = func() Plan {
	p := resolvePlan(PlanCommunity)
	p.Name, p.SeatCap, p.ResourceCap = PlanInactive, 0, 0
	return p
}()

func (p Plan) Has(feature string) bool {
	for _, f := range CatalogFeatures {
		if f.Code == feature {
			return planRank(p.Name) >= planRank(f.Plan)
		}
	}
	return false
}

// planRank is -1 for a name that is no plan, so a zero Plan has nothing. Inactive ranks as Community.
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
