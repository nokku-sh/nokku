// Package entitlement is the single enforcement point for plan logic. Money
// movement lives in internal/billing.
//
//   - Fail open on quotas, billing data problems never block daily work.
//   - Fail closed on features, resolution errors fall back to Community.
//   - Downgrades never destroy data right away. An ended plan or license
//     keeps its data limits for holdDays.
package entitlement

import "maps"

const (
	FeatureOIDC           = "oidc"
	FeatureEnforceSSO     = "enforce_sso"
	FeatureSAML           = "saml"
	FeatureSCIM           = "scim"
	FeatureAuditExport    = "audit_export"
	FeatureAuditStreaming = "audit_streaming"
	FeatureExternalKMS    = "external_kms"
)

const (
	PlanCommunity  = "community"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

type Feature struct {
	Code  string
	Label string
}

var CatalogFeatures = []Feature{
	{FeatureOIDC, "OIDC single sign-on"},
	{FeatureEnforceSSO, "enforced single sign-on"},
	{FeatureSAML, "SAML single sign-on"},
	{FeatureSCIM, "SCIM provisioning"},
	{FeatureAuditExport, "audit log export"},
	{FeatureAuditStreaming, "audit log streaming"},
	{FeatureExternalKMS, "external key management"},
}

func featureInCatalog(code string) (Feature, bool) {
	for _, f := range CatalogFeatures {
		if f.Code == code {
			return f, true
		}
	}
	return Feature{}, false
}

const unlimited int64 = -1

type Plan struct {
	Name          string
	SeatCap       int64 // maximum members; unlimited = per-seat billing
	ResourceCap   int64 // pooled cap on managed resources
	RetentionDays int64 // audit log and session recording retention
	// RecordingStorageBytes is a stop for abuse, sized so that normal use
	// runs into the retention first.
	RecordingStorageBytes int64
	Features              map[string]bool
}

func (p Plan) Has(feature string) bool {
	return p.Features[feature]
}

var catalog = map[string]Plan{
	PlanCommunity: {
		Name:                  PlanCommunity,
		SeatCap:               5,
		ResourceCap:           50,
		RetentionDays:         7,
		RecordingStorageBytes: 1 << 30,
		Features: map[string]bool{
			FeatureOIDC: true,
		},
	},
	PlanPro: {
		Name:                  PlanPro,
		SeatCap:               unlimited,
		ResourceCap:           2000,
		RetentionDays:         90,
		RecordingStorageBytes: 50 << 30,
		Features: map[string]bool{
			FeatureOIDC:        true,
			FeatureEnforceSSO:  true,
			FeatureSAML:        true,
			FeatureAuditExport: true,
		},
	},
	PlanEnterprise: {
		Name:                  PlanEnterprise,
		SeatCap:               unlimited,
		ResourceCap:           unlimited,
		RetentionDays:         365,
		RecordingStorageBytes: 500 << 30,
		Features: map[string]bool{
			FeatureOIDC:           true,
			FeatureEnforceSSO:     true,
			FeatureSAML:           true,
			FeatureSCIM:           true,
			FeatureAuditExport:    true,
			FeatureAuditStreaming: true,
			FeatureExternalKMS:    true,
		},
	},
}

func resolvePlan(name string) Plan {
	switch name {
	case PlanCommunity, PlanPro, PlanEnterprise:
	default:
		name = PlanCommunity
	}
	base := catalog[name]
	return Plan{
		Name:                  name,
		SeatCap:               base.SeatCap,
		ResourceCap:           base.ResourceCap,
		RetentionDays:         base.RetentionDays,
		RecordingStorageBytes: base.RecordingStorageBytes,
		Features:              maps.Clone(base.Features),
	}
}
