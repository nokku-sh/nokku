package billing

import (
	"testing"

	"github.com/nokku-sh/nokku/internal/db"
)

func TestStatus_GrantsAccess(t *testing.T) {
	tests := []struct {
		status Status
		want   bool
	}{
		{StatusActive, true},
		{StatusTrialing, true},
		{StatusPastDue, true},
		{StatusInactive, false},
		{Status("bogus"), false}, // unknown statuses fail closed
		{Status(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.GrantsAccess(); got != tt.want {
				t.Errorf("GrantsAccess(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestActiveStatuses(t *testing.T) {
	want := []string{"active", "trialing", "past_due"}
	if len(ActiveStatuses) != len(want) {
		t.Fatalf("ActiveStatuses = %v, want %v", ActiveStatuses, want)
	}
	for i, w := range want {
		if ActiveStatuses[i] != w {
			t.Errorf("ActiveStatuses[%d] = %q, want %q", i, ActiveStatuses[i], w)
		}
	}
}

func TestResolvePlan_KnownAndUnknown(t *testing.T) {
	tests := []struct {
		name string
		plan string
	}{
		{"community", PlanCommunity},
		{"flex", PlanFlex},
		{"enterprise", PlanEnterprise},
		{"unknown falls back to community", "gold"},
		{"empty falls back to community", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolvePlan(tt.plan)
			wantPlan := tt.plan
			if tt.plan != PlanCommunity && tt.plan != PlanFlex && tt.plan != PlanEnterprise {
				wantPlan = PlanCommunity
			}
			if got.Limits[ResourceMembers] != catalog[wantPlan].Limits[ResourceMembers] {
				t.Errorf(
					"resolvePlan(%q) members quota = %+v, want %+v (plan %s)",
					tt.plan,
					got.Limits[ResourceMembers],
					catalog[wantPlan].Limits[ResourceMembers],
					wantPlan,
				)
			}
		})
	}
}

func TestResolvePlan_ReturnsCopies(t *testing.T) {
	plan := resolvePlan(PlanCommunity)

	// Mutating the resolved plan must not corrupt the catalog.
	plan.Limits[ResourceMembers] = Quota{Soft: 1, Hard: 1}
	plan.Features["hacked"] = true
	plan.Values["hacked"] = 1

	again := resolvePlan(PlanCommunity)
	if again.Limits[ResourceMembers] != catalog[PlanCommunity].Limits[ResourceMembers] {
		t.Error("catalog corrupted by resolved plan mutation")
	}
	if again.Features["hacked"] {
		t.Error("catalog features corrupted by resolved plan mutation")
	}
	if _, ok := again.Values["hacked"]; ok {
		t.Error("catalog values corrupted by resolved plan mutation")
	}
}

func TestQuotaError_Error(t *testing.T) {
	err := &QuotaError{Resource: ResourceMembers, Limit: 5}
	want := "members limit (5) reached for your current plan"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCurrentCount(t *testing.T) {
	stats := &db.GetWorkspaceStatsRow{
		MemberCount:         1,
		ServiceAccountCount: 2,
		TargetCount:         3,
		TeamCount:           4,
		CaCount:             5,
	}

	tests := []struct {
		resource Resource
		want     int64
	}{
		{ResourceMembers, 1},
		{ResourceServiceAccounts, 2},
		{ResourceTargets, 3},
		{ResourceTeams, 4},
		{ResourceCas, 5},
		{Resource("bogus"), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.resource), func(t *testing.T) {
			if got := currentCount(stats, tt.resource); got != tt.want {
				t.Errorf("currentCount(%q) = %d, want %d", tt.resource, got, tt.want)
			}
		})
	}
}
