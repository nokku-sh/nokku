// Package entitlement is the only place plan logic is enforced. Quotas fail open, features fail closed.
package entitlement

import "slices"

const (
	FeatureOIDC        = "oidc"
	FeatureEnforceSSO  = "enforce_sso"
	FeatureSCIM        = "scim"
	FeatureAuditExport = "audit_export"
	FeatureExternalKMS = "external_kms"
)

const (
	PlanCommunity  = "community"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

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
	{FeatureSCIM, "SCIM provisioning", PlanEnterprise},
	{FeatureExternalKMS, "external key management", PlanEnterprise},
}

const unlimited int64 = -1

type Plan struct {
	Name          string
	SeatCap       int64 // maximum members, unlimited means per-seat billing
	ResourceCap   int64 // pooled cap on managed resources
	RetentionDays int64 // audit log and session recording retention
	// RecordingStorageBytes is a stop for abuse, sized so that normal use runs into the retention first.
	RecordingStorageBytes int64
}

// plans go from the smallest to the largest, Has depends on the order.
var plans = []Plan{
	{
		Name:                  PlanCommunity,
		SeatCap:               5,
		ResourceCap:           50,
		RetentionDays:         7,
		RecordingStorageBytes: 1 << 30,
	},
	{
		Name:                  PlanPro,
		SeatCap:               unlimited,
		ResourceCap:           2000,
		RetentionDays:         90,
		RecordingStorageBytes: 50 << 30,
	},
	{
		Name:                  PlanEnterprise,
		SeatCap:               unlimited,
		ResourceCap:           unlimited,
		RetentionDays:         365,
		RecordingStorageBytes: 500 << 30,
	},
}

func (p Plan) Has(feature string) bool {
	for _, f := range CatalogFeatures {
		if f.Code == feature {
			return planRank(p.Name) >= planRank(f.Plan)
		}
	}
	return false
}

// planRank is -1 for a name that is no plan, so a zero Plan has nothing.
func planRank(name string) int {
	return slices.IndexFunc(plans, func(p Plan) bool { return p.Name == name })
}

// resolvePlan reads an unknown name as Community.
func resolvePlan(name string) Plan {
	return plans[max(planRank(name), 0)]
}
