package entitlement

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A cell here is a pricing decision. Update docs, pricing page and Stripe too.
func TestPlanMatrix(t *testing.T) {
	tests := []struct {
		plan            string
		wantSeatCap     int64
		wantResourceCap int64
		wantAudit       int64
		wantRecordings  int64
		wantStorageCap  int64
		wantFeatures    map[string]bool
	}{
		{
			plan:            PlanCommunity,
			wantSeatCap:     5,
			wantResourceCap: 50,
			wantAudit:       30,
			wantRecordings:  7,
			wantStorageCap:  1 << 30,
			wantFeatures: map[string]bool{
				FeatureEnforceSSO:     false,
				FeatureAuditExport:    false,
				FeatureExpiringAccess: false,
				FeatureAccessReview:   false,
				FeatureIdleTimeout:    false,
				FeatureAccessRequests: false,
				FeatureAuditStreaming: false,
			},
		},
		{
			plan:            PlanPro,
			wantSeatCap:     unlimited,
			wantResourceCap: 2000,
			wantAudit:       90,
			wantRecordings:  90,
			wantStorageCap:  50 << 30,
			wantFeatures: map[string]bool{
				FeatureEnforceSSO:     true,
				FeatureAuditExport:    true,
				FeatureExpiringAccess: true,
				FeatureAccessReview:   true,
				FeatureIdleTimeout:    true,
				FeatureAccessRequests: false,
				FeatureAuditStreaming: false,
			},
		},
		{
			plan:            PlanEnterprise,
			wantSeatCap:     unlimited,
			wantResourceCap: unlimited,
			wantAudit:       365,
			wantRecordings:  365,
			wantStorageCap:  500 << 30,
			wantFeatures: map[string]bool{
				FeatureEnforceSSO:     true,
				FeatureAuditExport:    true,
				FeatureExpiringAccess: true,
				FeatureAccessReview:   true,
				FeatureIdleTimeout:    true,
				FeatureAccessRequests: true,
				FeatureAuditStreaming: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.plan, func(t *testing.T) {
			plan := resolvePlan(tt.plan)
			assert.Equal(t, tt.plan, plan.Name)
			assert.Equal(t, tt.wantSeatCap, plan.SeatCap, "SeatCap")
			assert.Equal(t, tt.wantResourceCap, plan.ResourceCap, "ResourceCap")
			assert.Equal(t, tt.wantAudit, plan.AuditRetentionDays, "AuditRetentionDays")
			assert.Equal(t, tt.wantRecordings, plan.RecordingRetentionDays, "RecordingRetentionDays")
			assert.Equal(t, tt.wantStorageCap, plan.RecordingStorageBytes, "RecordingStorageBytes")
			for feature, want := range tt.wantFeatures {
				assert.Equal(t, want, plan.Has(feature), "Has(%q)", feature)
			}
		})
	}
}

func TestResolvePlan_Unknown(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"unknown falls back to community", "gold", PlanCommunity},
		{"empty falls back to community", "", PlanCommunity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolvePlan(tt.input).Name)
		})
	}
}

// A plan that was never resolved has nothing, not even what Community has.
func TestZeroPlanHasNoFeature(t *testing.T) {
	for _, feature := range CatalogFeatures {
		assert.False(t, (Plan{}).Has(feature.Code), "a zero Plan has %q", feature.Code)
	}
	assert.False(t, resolvePlan(PlanEnterprise).Has("no_such_feature"),
		"Enterprise has a feature that is not in the catalog")
}

func TestInactive_KeepsTheFreeFeaturesAndLimits(t *testing.T) {
	community := resolvePlan(PlanCommunity)
	const keeps = "an inactive workspace keeps its data like Community"
	assert.Equal(t, community.AuditRetentionDays, inactive.AuditRetentionDays, keeps)
	assert.Equal(t, community.RecordingRetentionDays, inactive.RecordingRetentionDays, keeps)
	assert.Zero(t, inactive.SeatCap, "an inactive workspace takes no new seats")
	assert.Zero(t, inactive.ResourceCap, "an inactive workspace takes no new resources")
	for _, f := range CatalogFeatures {
		assert.Equal(t, f.Plan == PlanCommunity, inactive.Has(f.Code), "inactive.Has(%q)", f.Code)
	}
	assert.Equal(t, PlanCommunity, resolvePlan(PlanInactive).Name,
		"inactive must never come out of resolvePlan, a self-hosted server has no such plan")
}
