package billing

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/db"
)

type fakeLicenser struct{ valid bool }

func (f fakeLicenser) Valid() bool { return f.valid }

type stubQuerier struct {
	sub *db.WorkspaceSubscription
	err error

	stats *db.GetWorkspaceStatsRow
}

func (s *stubQuerier) GetSubscription(context.Context, string) (*db.WorkspaceSubscription, error) {
	return s.sub, s.err
}

func (s *stubQuerier) GetWorkspaceStats(context.Context, string) (*db.GetWorkspaceStatsRow, error) {
	return s.stats, s.err
}

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

func TestService_Resolve_ActiveLicenseOverrides(t *testing.T) {
	svc := NewPolicyService(&stubQuerier{}, fakeLicenser{valid: true})

	plan := svc.Resolve(context.Background(), "ws-1")
	if plan.Limits[ResourceMembers].Hard != -1 {
		t.Errorf(
			"licensed instance should resolve to enterprise (unlimited), got %+v",
			plan.Limits[ResourceMembers],
		)
	}
	if !plan.Features[FeatureEnforceSSO] {
		t.Error("enterprise should have enforce_sso")
	}
}

func TestService_Resolve_SaaSDoesNotUseInstanceLicense(t *testing.T) {
	svc := NewPolicyService(&stubQuerier{}, fakeLicenser{valid: true}, ModeSaaS)

	plan := svc.Resolve(context.Background(), "ws-1")
	if plan.Name != PlanCommunity {
		t.Errorf("SaaS instance license should be ignored, got plan %q", plan.Name)
	}
}

func TestService_Resolve_SubscriptionStatus(t *testing.T) {
	tests := []struct {
		name  string
		sub   *db.WorkspaceSubscription
		dbErr error
		want  string
	}{
		{
			"active flex",
			&db.WorkspaceSubscription{Plan: PlanFlex, Status: string(StatusActive)},
			nil,
			PlanFlex,
		},
		{
			"trialing community",
			&db.WorkspaceSubscription{Plan: PlanCommunity, Status: string(StatusTrialing)},
			nil,
			PlanCommunity,
		},
		{
			"past due keeps plan",
			&db.WorkspaceSubscription{Plan: PlanEnterprise, Status: string(StatusPastDue)},
			nil,
			PlanEnterprise,
		},
		{
			"inactive falls back to community",
			&db.WorkspaceSubscription{Plan: PlanEnterprise, Status: string(StatusInactive)},
			nil,
			PlanCommunity,
		},
		{
			"unknown status fails closed",
			&db.WorkspaceSubscription{Plan: PlanFlex, Status: "weird"},
			nil,
			PlanCommunity,
		},
		{
			"empty status fails closed",
			&db.WorkspaceSubscription{Plan: PlanFlex, Status: ""},
			nil,
			PlanCommunity,
		},
		{"db error falls back to community", nil, errors.New("db down"), PlanCommunity},
		{"missing subscription falls back to community", nil, nil, PlanCommunity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewPolicyService(
				&stubQuerier{sub: tt.sub, err: tt.dbErr},
				fakeLicenser{valid: false},
			)

			plan := svc.Resolve(context.Background(), "ws-1")
			if got := plan.Limits[ResourceMembers]; got != catalog[tt.want].Limits[ResourceMembers] {
				t.Errorf(
					"Resolve() members quota = %+v, want %+v (plan %s)",
					got,
					catalog[tt.want].Limits[ResourceMembers],
					tt.want,
				)
			}
		})
	}
}

func TestFlexIncludesSSOFeatures(t *testing.T) {
	svc := NewPolicyService(&stubQuerier{
		sub: &db.WorkspaceSubscription{Plan: PlanFlex, Status: string(StatusActive)},
	}, fakeLicenser{valid: false})

	ctx := context.Background()
	for _, feature := range []string{FeatureOIDC, FeatureSAML, FeatureEnforceSSO} {
		if !svc.Has(ctx, "ws-1", feature) {
			t.Errorf("Flex should include %s", feature)
		}
	}
}

func TestService_Has_And_Int(t *testing.T) {
	svc := NewPolicyService(&stubQuerier{}, fakeLicenser{valid: false})
	ctx := context.Background()

	// No subscription row => community plan.
	if svc.Has(ctx, "ws-1", FeatureEnforceSSO) {
		t.Error("community must not have enforce_sso")
	}
	if got := svc.Int(ctx, "ws-1", ValueAuditRetentionDays, 999); got != 7 {
		t.Errorf("community retention = %d, want 7", got)
	}
	if got := svc.Int(ctx, "ws-1", "unknown_key", 42); got != 42 {
		t.Errorf("unknown value fallback = %d, want 42", got)
	}
}

func TestService_Has_OnLicensedInstance(t *testing.T) {
	svc := NewPolicyService(&stubQuerier{}, fakeLicenser{valid: true})
	if !svc.Has(context.Background(), "ws-1", FeatureEnforceSSO) {
		t.Error("licensed instance must have enforce_sso")
	}
}

func TestService_Check_QuotaExceeded(t *testing.T) {
	svc := NewPolicyService(&stubQuerier{
		sub:   &db.WorkspaceSubscription{Plan: PlanCommunity, Status: string(StatusActive)},
		stats: &db.GetWorkspaceStatsRow{MemberCount: 5}, // community hard cap: 5
	}, fakeLicenser{valid: false})

	err := svc.Check(context.Background(), "ws-1", ResourceMembers)
	if err == nil {
		t.Fatal("Check() at cap: want error")
	}
	var quotaErr *QuotaError
	if !errors.As(err, &quotaErr) {
		t.Fatalf("error type = %T, want *QuotaError", err)
	}
	if quotaErr.Resource != ResourceMembers || quotaErr.Limit != 5 {
		t.Errorf("QuotaError = %+v, want members/5", quotaErr)
	}
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", connect.CodeOf(err))
	}
}

func TestService_Check_UnderQuota(t *testing.T) {
	svc := NewPolicyService(&stubQuerier{
		sub:   &db.WorkspaceSubscription{Plan: PlanCommunity, Status: string(StatusActive)},
		stats: &db.GetWorkspaceStatsRow{MemberCount: 4},
	}, fakeLicenser{valid: false})

	if err := svc.Check(context.Background(), "ws-1", ResourceMembers); err != nil {
		t.Errorf("Check() under cap: %v", err)
	}
}

func TestService_Check_FailsClosedOnStatsError(t *testing.T) {
	tests := []struct {
		name    string
		q       *stubQuerier
		wantErr bool
	}{
		{
			"stats db error",
			&stubQuerier{
				sub: &db.WorkspaceSubscription{Plan: PlanCommunity, Status: string(StatusActive)},
				err: errors.New("db down"),
			},
			true,
		},
		{
			"unlimited plan",
			&stubQuerier{
				sub:   &db.WorkspaceSubscription{Plan: PlanFlex, Status: string(StatusActive)},
				stats: &db.GetWorkspaceStatsRow{MemberCount: 999},
			},
			false,
		},
		{
			"unknown resource",
			&stubQuerier{
				sub:   &db.WorkspaceSubscription{Plan: PlanCommunity, Status: string(StatusActive)},
				stats: &db.GetWorkspaceStatsRow{},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewPolicyService(tt.q, fakeLicenser{valid: false})
			err := svc.Check(context.Background(), "ws-1", ResourceMembers)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}
