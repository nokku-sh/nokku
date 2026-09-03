// Package entitlement resolves what a workspace's plan allows: seats,
// retention, and org-level feature gates. It is the single enforcement
// point for plan logic; money movement (Stripe, license keys) lives in
// internal/billing.
//
// Design rules (see idea/billing-and-monetization.md §5.2):
//   - Fail open on quota (seats): billing data problems never block daily
//     work. Fail closed on features: resolution errors fall back to
//     Community, and the admin sees the missing feature, not silent access.
//   - Downgrades never destroy data. Features stop, retention shrinks on
//     its normal schedule, nothing is deleted on plan change.
//   - One Resolve per request, cached in context, like authn.
//   - The catalog lives in code and ships in the public binary. That is
//     transparency, not leakage: prices reference the catalog by name, the
//     Ed25519 signing key is the only secret in the system.
package entitlement

import "maps"

const (
	FeatureOIDC        = "oidc"
	FeatureEnforceSSO  = "enforce_sso"
	FeatureSAML        = "saml"
	FeatureAuditExport = "audit_export"
	FeatureExternalKMS = "external_kms"
)

const (
	PlanCommunity  = "community"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

const Unlimited int64 = -1

type Plan struct {
	Name                  string
	SeatCap               int64 // maximum members; Unlimited = per-seat billing
	ResourceCap           int64 // pooled cap on managed resources
	RetentionDays         int64 // audit log and session recording retention
	RecordingStorageBytes int64
	Features              map[string]bool
}

// Has reports whether the plan enables the feature.
func (p Plan) Has(feature string) bool {
	return p.Features[feature]
}

var catalog = map[string]Plan{
	PlanCommunity: {
		Name:                  PlanCommunity,
		SeatCap:               5,
		ResourceCap:           50,
		RetentionDays:         7,
		RecordingStorageBytes: 10 << 20,
		Features: map[string]bool{
			FeatureOIDC: true,
		},
	},
	PlanPro: {
		Name:                  PlanPro,
		SeatCap:               Unlimited,
		ResourceCap:           2000,
		RetentionDays:         90,
		RecordingStorageBytes: 100 << 20,
		Features: map[string]bool{
			FeatureOIDC:        true,
			FeatureEnforceSSO:  true,
			FeatureSAML:        true,
			FeatureAuditExport: true,
		},
	},
	PlanEnterprise: {
		Name:                  PlanEnterprise,
		SeatCap:               Unlimited,
		RetentionDays:         365,
		RecordingStorageBytes: 1 << 30,
		Features: map[string]bool{
			FeatureOIDC:        true,
			FeatureEnforceSSO:  true,
			FeatureSAML:        true,
			FeatureAuditExport: true,
			FeatureExternalKMS: true,
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
