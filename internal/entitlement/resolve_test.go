package entitlement

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mizuchilabs/kata/licx"

	"github.com/nokku-sh/nokku/internal/db"
)

// fakeDB fakes the transactional surface the resolver reads through. It
// doubles as the sqlc DBTX underneath, serving the two queries entitlement
// issues: the workspace subscription row and the pooled resource count.
// The mode NewService takes, named so the calls read.
const (
	modeSaaS       = true
	modeSelfHosted = false
)

type fakeDB struct {
	plan        string
	status      Status
	seats       int64
	endedAt     *time.Time
	licenseKey  string
	subErr      error
	resources   int64
	resourceErr error
}

func (f *fakeDB) WithTx(_ context.Context, fn func(*db.Queries) error) error {
	return fn(db.New(f))
}

func (f *fakeDB) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (f *fakeDB) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return nil, errors.New("entitlement test: unexpected query")
}

func (f *fakeDB) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "workspace_subscriptions"):
		if f.subErr != nil {
			return errRow{f.subErr}
		}
		return rowVals{vals: []any{
			"ws1", "stripe", f.plan, string(f.status),
			"cus_1", "sub_1", nil, false,
			f.seats, f.endedAt,
			time.Time{},
		}}
	case strings.Contains(sql, "instance_license"):
		if f.licenseKey == "" {
			return errRow{pgx.ErrNoRows}
		}
		return rowVals{vals: []any{f.licenseKey}}
	case strings.Contains(sql, "resource_count"):
		if f.resourceErr != nil {
			return errRow{f.resourceErr}
		}
		return rowVals{vals: []any{f.resources}}
	default:
		panic("entitlement test: unexpected query row: " + sql)
	}
}

// errRow is a pgx.Row that always fails with err.
type errRow struct{ err error }

func (r errRow) Scan(_ ...any) error { return r.err }

// rowVals scans one row positionally into the sqlc-generated destinations
// for the queries above.
type rowVals struct{ vals []any }

func (r rowVals) Scan(dest ...any) error {
	if len(r.vals) != len(dest) {
		return pgx.ErrNoRows
	}
	for i, d := range dest {
		switch out := d.(type) {
		case *string:
			*out = r.vals[i].(string)
		case *bool:
			*out = r.vals[i].(bool)
		case *time.Time:
			*out = r.vals[i].(time.Time)
		case **time.Time:
			*out, _ = r.vals[i].(*time.Time)
		case *int64:
			*out = r.vals[i].(int64)
		default:
			return fmt.Errorf("rowVals: unsupported dest %T", d)
		}
	}
	return nil
}

// licensed is an unexpired license for plan, or none for "".
func licensed(plan string) *licx.Claims {
	if plan == "" {
		return nil
	}
	return &licx.Claims{Plan: plan}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		db      *fakeDB
		license string
		mode    bool
		want    string
	}{
		{
			name: "modeSaaS active subscription",
			db:   &fakeDB{plan: PlanPro, status: StatusActive},
			mode: modeSaaS,
			want: PlanPro,
		},
		{
			name: "trialing grants access",
			db:   &fakeDB{plan: PlanEnterprise, status: StatusTrialing},
			mode: modeSaaS,
			want: PlanEnterprise,
		},
		{
			name: "past due keeps access (grace period)",
			db:   &fakeDB{plan: PlanPro, status: StatusPastDue},
			mode: modeSaaS,
			want: PlanPro,
		},
		{
			name: "canceled subscription falls back to community",
			db:   &fakeDB{plan: PlanPro, status: StatusInactive},
			mode: modeSaaS,
			want: PlanCommunity,
		},
		{
			name: "no subscription row falls back to community",
			db:   &fakeDB{subErr: errors.New("no rows")},
			mode: modeSaaS,
			want: PlanCommunity,
		},
		{
			// pgx.ErrNoRows is the normal community case, not a failure.
			name: "pgx ErrNoRows is the quiet community path",
			db:   &fakeDB{subErr: pgx.ErrNoRows},
			mode: modeSaaS,
			want: PlanCommunity,
		},
		{
			name:    "self-hosted valid license grants licensed plan",
			db:      &fakeDB{},
			mode:    modeSelfHosted,
			license: PlanEnterprise,
			want:    PlanEnterprise,
		},
		{
			name:    "self-hosted license with unknown plan resolves to community",
			db:      &fakeDB{},
			mode:    modeSelfHosted,
			license: "ultimate",
			want:    PlanCommunity,
		},
		{
			name:    "invalid license ignores subscription-less workspace",
			db:      &fakeDB{subErr: errors.New("no rows")},
			mode:    modeSelfHosted,
			license: "",
			want:    PlanCommunity,
		},
		{
			name:    "subscription wins over invalid license",
			db:      &fakeDB{plan: PlanPro, status: StatusActive},
			mode:    modeSelfHosted,
			license: "",
			want:    PlanPro,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sut := NewService(tt.db, licensed(tt.license), tt.mode)
			got := sut.Resolve(t.Context(), "ws1")
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
		modeSaaS,
	)
	got := sut.Resolve(t.Context(), "ws1")
	if got.Has(FeatureSCIM) || got.Has(FeatureAuditExport) || got.Has(FeatureEnforceSSO) {
		t.Error("DB error granted paid features")
	}
	if got.Name != PlanCommunity {
		t.Errorf("DB error resolved to %q, want community", got.Name)
	}
}

func TestRetentionDays_ErrorsOnDBError(t *testing.T) {
	// The purge jobs skip on error, a billing outage must never delete data.
	broken := NewService(&fakeDB{subErr: errors.New("connection refused")}, nil, modeSaaS)
	if _, err := broken.RetentionDays(t.Context(), "ws1"); err == nil {
		t.Error("DB error returned a retention window instead of an error")
	}

	free := NewService(&fakeDB{subErr: pgx.ErrNoRows}, nil, modeSaaS)
	days, err := free.RetentionDays(t.Context(), "ws1")
	if err != nil || days != 7 {
		t.Errorf("no subscription row = %d, %v, want 7 days and no error", days, err)
	}
}

func TestResolve_SelfHostedLicensedPlanUnlimited(t *testing.T) {
	// The licensed self-hosted branch resolves its plan straight from the
	// catalog, but the caps still protect SaaS infrastructure only. An
	// enterprise key must enroll daemons, not hit ResourceCap zero from the
	// catalog entry.
	sut := NewService(
		&fakeDB{},
		licensed(PlanEnterprise),
		modeSelfHosted,
	)
	got := sut.Resolve(t.Context(), "ws1")

	if got.Name != PlanEnterprise {
		t.Errorf("Resolve() = %q, want enterprise", got.Name)
	}
	if got.ResourceCap != unlimited {
		t.Errorf("self-hosted licensed ResourceCap = %d, want unlimited", got.ResourceCap)
	}
	if got.RecordingStorageBytes != unlimited {
		t.Errorf("self-hosted licensed storage cap = %d, want unlimited", got.RecordingStorageBytes)
	}
	if err := sut.CheckResources(t.Context(), "ws1"); err != nil {
		t.Errorf("CheckResources() = %v, want nil", err)
	}
}

func TestResolve_SelfHostedRecordingStorageUnlimited(t *testing.T) {
	// The recording storage cap protects SaaS infrastructure only. On
	// self-hosted, the disk is the customer's own whatever the plan says.
	sut := NewService(
		&fakeDB{plan: PlanEnterprise, status: StatusActive},
		nil,
		modeSelfHosted,
	)
	// Even with no subscription and no license: unlimited, not 10 MiB.
	bare := NewService(&fakeDB{}, nil, modeSelfHosted)

	if got, _ := sut.RecordingStorageBytes(t.Context(), "ws1"); got != unlimited {
		t.Errorf("self-hosted pro storage cap = %d, want unlimited", got)
	}
	if got, _ := bare.RecordingStorageBytes(t.Context(), "ws1"); got != unlimited {
		t.Errorf("self-hosted community storage cap = %d, want unlimited", got)
	}
}

func TestResolve_RequestCache(t *testing.T) {
	db := &fakeDB{plan: PlanPro, status: StatusActive}
	sut := NewService(db, nil, modeSaaS)

	ctx := withRequestCache(t.Context())
	first := sut.Resolve(ctx, "ws1")
	db.plan = PlanCommunity // mutate behind the cache
	second := sut.Resolve(ctx, "ws1")

	if first.Name != PlanPro || second.Name != PlanPro {
		t.Errorf("cache miss: first = %q, second = %q, want both pro", first.Name, second.Name)
	}

	// A fresh context must see the mutation.
	fresh := sut.Resolve(t.Context(), "ws1")
	if fresh.Name != PlanCommunity {
		t.Errorf("fresh resolve = %q, want community", fresh.Name)
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
			sut := NewService(tt.db, nil, modeSaaS)
			err := sut.CanInvite(t.Context(), "ws1", tt.members)
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
			if got := tt.status.grantsAccess(); got != tt.want {
				t.Errorf("grantsAccess(%q) = %v, want %v", tt.status, got, tt.want)
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
