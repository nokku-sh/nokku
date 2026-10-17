package entitlement

import (
	"testing"
)

// Changing a cell here is a pricing decision. It comes with a docs, pricing page and Stripe update.
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
				FeatureOIDC:        true,
				FeatureEnforceSSO:  false,
				FeatureAuditExport: false,
				FeatureExternalKMS: true,
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
				FeatureOIDC:        true,
				FeatureEnforceSSO:  true,
				FeatureAuditExport: true,
				FeatureExternalKMS: true,
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
				FeatureOIDC:        true,
				FeatureEnforceSSO:  true,
				FeatureAuditExport: true,
				FeatureExternalKMS: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.plan, func(t *testing.T) {
			plan := resolvePlan(tt.plan)
			if plan.Name != tt.plan {
				t.Errorf("Name = %q, want %q", plan.Name, tt.plan)
			}
			if plan.SeatCap != tt.wantSeatCap {
				t.Errorf("SeatCap = %d, want %d", plan.SeatCap, tt.wantSeatCap)
			}
			if plan.ResourceCap != tt.wantResourceCap {
				t.Errorf("ResourceCap = %d, want %d", plan.ResourceCap, tt.wantResourceCap)
			}
			if plan.AuditRetentionDays != tt.wantAudit {
				t.Errorf("AuditRetentionDays = %d, want %d", plan.AuditRetentionDays, tt.wantAudit)
			}
			if plan.RecordingRetentionDays != tt.wantRecordings {
				t.Errorf("RecordingRetentionDays = %d, want %d", plan.RecordingRetentionDays, tt.wantRecordings)
			}
			if plan.RecordingStorageBytes != tt.wantStorageCap {
				t.Errorf(
					"RecordingStorageBytes = %d, want %d",
					plan.RecordingStorageBytes,
					tt.wantStorageCap,
				)
			}
			for feature, want := range tt.wantFeatures {
				if got := plan.Has(feature); got != want {
					t.Errorf("Has(%q) = %v, want %v", feature, got, want)
				}
			}
		})
	}
}

func TestResolvePlan_LegacyAndUnknown(t *testing.T) {
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
			if got := resolvePlan(tt.input).Name; got != tt.want {
				t.Errorf("resolvePlan(%q).Name = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// A plan that was never resolved has nothing, not even what Community has.
func TestZeroPlanHasNoFeature(t *testing.T) {
	for _, feature := range CatalogFeatures {
		if (Plan{}).Has(feature.Code) {
			t.Errorf("a zero Plan has %q", feature.Code)
		}
	}
	if resolvePlan(PlanEnterprise).Has("no_such_feature") {
		t.Error("Enterprise has a feature that is not in the catalog")
	}
}

func TestInactive_KeepsTheFreeFeaturesAndLimits(t *testing.T) {
	community := resolvePlan(PlanCommunity)
	if inactive.AuditRetentionDays != community.AuditRetentionDays ||
		inactive.RecordingRetentionDays != community.RecordingRetentionDays {
		t.Error("an inactive workspace keeps its data like Community")
	}
	if inactive.SeatCap != 0 || inactive.ResourceCap != 0 {
		t.Error("an inactive workspace takes nothing new")
	}
	for _, f := range CatalogFeatures {
		if want := f.Plan == PlanCommunity; inactive.Has(f.Code) != want {
			t.Errorf("inactive.Has(%q) = %v, want %v", f.Code, !want, want)
		}
	}
	if resolvePlan(PlanInactive).Name != PlanCommunity {
		t.Error("inactive must never come out of resolvePlan, a self-hosted server has no such plan")
	}
}
