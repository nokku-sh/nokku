package entitlement

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// fakeDB is a narrow in-memory DB for resolver tests.
type fakeDB struct {
	plan        string
	status      Status
	subErr      error
	resources   int64
	resourceErr error
}

func (f *fakeDB) Subscription(_ context.Context, _ string) (string, Status, error) {
	if f.subErr != nil {
		return "", StatusInactive, f.subErr
	}
	return f.plan, f.status, nil
}

func (f *fakeDB) ResourceCount(_ context.Context, _ string) (int64, error) {
	return f.resources, f.resourceErr
}

type fakeLicense struct {
	valid bool
	plan  string
}

func (f fakeLicense) Valid() bool          { return f.valid }
func (f fakeLicense) LicensedPlan() string { return f.plan }

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		db      *fakeDB
		license *fakeLicense
		mode    Mode
		want    string
	}{
		{
			name: "saas active subscription",
			db:   &fakeDB{plan: PlanPro, status: StatusActive},
			mode: ModeSaaS,
			want: PlanPro,
		},
		{
			name: "trialing grants access",
			db:   &fakeDB{plan: PlanEnterprise, status: StatusTrialing},
			mode: ModeSaaS,
			want: PlanEnterprise,
		},
		{
			name: "past due keeps access (grace period)",
			db:   &fakeDB{plan: PlanPro, status: StatusPastDue},
			mode: ModeSaaS,
			want: PlanPro,
		},
		{
			name: "canceled subscription falls back to community",
			db:   &fakeDB{plan: PlanPro, status: StatusInactive},
			mode: ModeSaaS,
			want: PlanCommunity,
		},
		{
			name: "no subscription row falls back to community",
			db:   &fakeDB{subErr: errors.New("no rows")},
			mode: ModeSaaS,
			want: PlanCommunity,
		},
		{
			// pgx.ErrNoRows is the normal community case, not a failure.
			name: "pgx ErrNoRows is the quiet community path",
			db:   &fakeDB{subErr: pgx.ErrNoRows},
			mode: ModeSaaS,
			want: PlanCommunity,
		},
		{
			name:    "self-hosted valid license grants licensed plan",
			db:      &fakeDB{},
			mode:    ModeSelfHosted,
			license: &fakeLicense{valid: true, plan: PlanEnterprise},
			want:    PlanEnterprise,
		},
		{
			name:    "self-hosted license with unknown plan degrades to enterprise",
			db:      &fakeDB{},
			mode:    ModeSelfHosted,
			license: &fakeLicense{valid: true, plan: "ultimate"},
			want:    PlanEnterprise,
		},
		{
			name:    "invalid license ignores subscription-less workspace",
			db:      &fakeDB{subErr: errors.New("no rows")},
			mode:    ModeSelfHosted,
			license: &fakeLicense{valid: false},
			want:    PlanCommunity,
		},
		{
			name:    "subscription wins over invalid license",
			db:      &fakeDB{plan: PlanPro, status: StatusActive},
			mode:    ModeSelfHosted,
			license: &fakeLicense{valid: false},
			want:    PlanPro,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sut := NewService(tt.db, tt.license, tt.mode)
			got := sut.Resolve(context.Background(), "ws1")
			if got.Name != tt.want {
				t.Errorf("Resolve() = %q, want %q", got.Name, tt.want)
			}
		})
	}
}

func TestResolve_FailClosedOnDBError(t *testing.T) {
	// A billing outage must never hand out paid features (§5.2).
	sut := NewService(
		&fakeDB{subErr: errors.New("connection refused")},
		nil,
		ModeSaaS,
	)
	got := sut.Resolve(context.Background(), "ws1")
	if got.Has(FeatureSAML) || got.Has(FeatureAuditExport) || got.Has(FeatureEnforceSSO) {
		t.Error("DB error granted paid features")
	}
	if got.Name != PlanCommunity {
		t.Errorf("DB error resolved to %q, want community", got.Name)
	}
}

func TestResolve_SelfHostedLicensedPlanUnlimited(t *testing.T) {
	// The licensed self-hosted branch resolves its plan straight from the
	// catalog, but the caps still protect SaaS infrastructure only. An
	// enterprise key must enroll daemons, not hit ResourceCap zero from the
	// catalog entry.
	sut := NewService(
		&fakeDB{},
		&fakeLicense{valid: true, plan: PlanEnterprise},
		ModeSelfHosted,
	)
	got := sut.Resolve(context.Background(), "ws1")

	if got.Name != PlanEnterprise {
		t.Errorf("Resolve() = %q, want enterprise", got.Name)
	}
	if got.ResourceCap != Unlimited {
		t.Errorf("self-hosted licensed ResourceCap = %d, want unlimited", got.ResourceCap)
	}
	if got.RecordingStorageBytes != Unlimited {
		t.Errorf("self-hosted licensed storage cap = %d, want unlimited", got.RecordingStorageBytes)
	}
	if err := sut.CheckResources(context.Background(), "ws1"); err != nil {
		t.Errorf("CheckResources() = %v, want nil", err)
	}
}

func TestResolve_SelfHostedRecordingStorageUnlimited(t *testing.T) {
	// The recording storage cap protects SaaS infrastructure only. On
	// self-hosted, the disk is the customer's own whatever the plan says.
	sut := NewService(
		&fakeDB{plan: PlanEnterprise, status: StatusActive},
		nil,
		ModeSelfHosted,
	)
	// Even with no subscription and no license: unlimited, not 10 MiB.
	bare := NewService(&fakeDB{}, nil, ModeSelfHosted)

	if got := sut.RecordingStorageBytes(context.Background(), "ws1"); got != Unlimited {
		t.Errorf("self-hosted pro storage cap = %d, want unlimited", got)
	}
	if got := bare.RecordingStorageBytes(context.Background(), "ws1"); got != Unlimited {
		t.Errorf("self-hosted community storage cap = %d, want unlimited", got)
	}
}

func TestResolve_RequestCache(t *testing.T) {
	db := &fakeDB{plan: PlanPro, status: StatusActive}
	sut := NewService(db, nil, ModeSaaS)

	ctx := WithRequestCache(context.Background())
	first := sut.Resolve(ctx, "ws1")
	db.plan = PlanCommunity // mutate behind the cache
	second := sut.Resolve(ctx, "ws1")

	if first.Name != PlanPro || second.Name != PlanPro {
		t.Errorf("cache miss: first = %q, second = %q, want both pro", first.Name, second.Name)
	}

	// A fresh context must see the mutation.
	fresh := sut.Resolve(context.Background(), "ws1")
	if fresh.Name != PlanCommunity {
		t.Errorf("fresh resolve = %q, want community", fresh.Name)
	}
}

func TestLicensedPlanFor(t *testing.T) {
	tests := []struct {
		name    string
		license License
		want    string
	}{
		{
			name:    "nil license yields community",
			license: nil,
			want:    PlanCommunity,
		},
		{
			name:    "invalid license yields community",
			license: &fakeLicense{valid: false, plan: PlanPro},
			want:    PlanCommunity,
		},
		{
			name:    "valid license honors its plan",
			license: &fakeLicense{valid: true, plan: PlanPro},
			want:    PlanPro,
		},
		{
			name:    "v1 key without plan defaults to enterprise",
			license: &fakeLicense{valid: true},
			want:    PlanEnterprise,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LicensedPlanFor(tt.license); got != tt.want {
				t.Errorf("LicensedPlanFor() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanInvite(t *testing.T) {
	tests := []struct {
		name    string
		db      *fakeDB
		members int64
		wantErr bool
	}{
		{
			name:    "under cap allows invite",
			db:      &fakeDB{},
			members: 4,
		},
		{
			name:    "at cap denies invite",
			db:      &fakeDB{},
			members: 5,
			wantErr: true,
		},
		{
			name:    "unlimited plan always allows",
			db:      &fakeDB{plan: PlanPro, status: StatusActive},
			members: 5000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sut := NewService(tt.db, nil, ModeSaaS)
			err := sut.CanInvite(context.Background(), "ws1", tt.members)
			if (err != nil) != tt.wantErr {
				t.Errorf("CanInvite() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
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
