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
		wantRetention   int64
		wantStorageCap  int64
		wantFeatures    map[string]bool
	}{
		{
			plan:            PlanCommunity,
			wantSeatCap:     5,
			wantResourceCap: 50,
			wantRetention:   7,
			wantStorageCap:  1 << 30,
			wantFeatures: map[string]bool{
				FeatureOIDC:           true,
				FeatureEnforceSSO:     false,
				FeatureAuditExport:    false,
				FeatureAuditStreaming: false,
				FeatureExternalKMS:    false,
			},
		},
		{
			plan:            PlanPro,
			wantSeatCap:     unlimited,
			wantResourceCap: 2000,
			wantRetention:   90,
			wantStorageCap:  50 << 30,
			wantFeatures: map[string]bool{
				FeatureOIDC:           true,
				FeatureEnforceSSO:     true,
				FeatureAuditExport:    true,
				FeatureAuditStreaming: false,
				FeatureExternalKMS:    false,
			},
		},
		{
			plan:            PlanEnterprise,
			wantSeatCap:     unlimited,
			wantResourceCap: unlimited,
			wantRetention:   365,
			wantStorageCap:  500 << 30,
			wantFeatures: map[string]bool{
				FeatureOIDC:           true,
				FeatureEnforceSSO:     true,
				FeatureAuditExport:    true,
				FeatureAuditStreaming: true,
				FeatureExternalKMS:    true,
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
			if plan.RetentionDays != tt.wantRetention {
				t.Errorf("RetentionDays = %d, want %d", plan.RetentionDays, tt.wantRetention)
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

func TestResolvePlan_ReturnsCopies(t *testing.T) {
	plan := resolvePlan(PlanCommunity)
	plan.Features["hacked"] = true

	again := resolvePlan(PlanCommunity)
	if again.Has("hacked") {
		t.Error("catalog features corrupted by resolved plan mutation")
	}
}
