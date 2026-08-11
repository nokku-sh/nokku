package billing

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

type fakeLicenser struct{ valid bool }

func (f fakeLicenser) Valid() bool { return f.valid }

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

// The tests below exercise PolicyService against a real, fully migrated
// database (see testConnection). They are skipped when the development
// PostgreSQL container (compose.test.yml) is not running.

func testConnection(t *testing.T) *db.Connection {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	admin, err := pgx.Connect(
		ctx,
		"postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
	)
	if err != nil {
		t.Skipf("test database not available (%v); start compose.test.yml", err)
	}

	dbName := fmt.Sprintf("nokku_billing_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		_ = admin.Close(cleanupCtx)
	})

	t.Setenv("NOKKU_DB_HOST", "localhost")
	t.Setenv("NOKKU_DB_PORT", "5432")
	t.Setenv("NOKKU_DB_NAME", dbName)
	t.Setenv("NOKKU_DB_USER", "postgres")
	t.Setenv("NOKKU_DB_PASSWORD", "postgres")

	conn, err := db.NewConnection(ctx)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	return conn
}

// seedSeq guarantees unique users (email/username are UNIQUE) when seeding
// multiple workspaces into the same test database.
var seedSeq int

func nextSeedSeq() int {
	seedSeq++
	return seedSeq
}

// seedWorkspace creates a user, a workspace (which also adds the owner as a
// member) and optionally a manual subscription row. It returns the workspace
// ID. Runs in system transactions, so no actor context is needed.
func seedWorkspace(t *testing.T, conn *db.Connection, sub *db.WorkspaceSubscription) string {
	t.Helper()

	n := nextSeedSeq()
	ctx := context.Background()
	var wsID string
	err := conn.WithTx(ctx, func(q *db.Queries) error {
		owner, err := q.CreateUser(ctx, &db.CreateUserParams{
			Name:     "Owner",
			Username: fmt.Sprintf("owner%d", n),
			Email:    fmt.Sprintf("owner%d@example.com", n),
		})
		if err != nil {
			return err
		}
		ws, err := q.CreateWorkspace(ctx, &db.CreateWorkspaceParams{
			Name:      "Test WS",
			CreatedBy: owner.ID,
		})
		if err != nil {
			return err
		}
		wsID = ws.ID

		if sub != nil {
			if err := q.UpsertSubscription(ctx, &db.UpsertSubscriptionParams{
				WorkspaceID: ws.ID,
				Source:      "manual",
				Plan:        sub.Plan,
				Status:      sub.Status,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seeding workspace: %v", err)
	}
	return wsID
}

// addMembers creates n additional users and adds them to the workspace,
// on top of the owner that seedWorkspace already added.
func addMembers(t *testing.T, conn *db.Connection, wsID string, n int) {
	t.Helper()

	ctx := context.Background()
	err := conn.WithTx(ctx, func(q *db.Queries) error {
		for i := range n {
			seq := nextSeedSeq()
			u, err := q.CreateUser(ctx, &db.CreateUserParams{
				Name:     fmt.Sprintf("Member %d", i),
				Username: fmt.Sprintf("member%d", seq),
				Email:    fmt.Sprintf("member%d@example.com", seq),
			})
			if err != nil {
				return err
			}
			if err := q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
				WorkspaceID: wsID,
				UserID:      u.ID,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("adding members: %v", err)
	}
}

func TestService_Resolve_ActiveLicenseOverrides(t *testing.T) {
	svc := NewPolicyService(testConnection(t), fakeLicenser{valid: true})

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
	conn := testConnection(t)
	wsID := seedWorkspace(t, conn, nil)
	svc := NewPolicyService(conn, fakeLicenser{valid: true}, ModeSaaS)

	plan := svc.Resolve(context.Background(), wsID)
	if plan.Name != PlanCommunity {
		t.Errorf("SaaS instance license should be ignored, got plan %q", plan.Name)
	}
}

func TestService_Resolve_SubscriptionStatus(t *testing.T) {
	conn := testConnection(t)

	tests := []struct {
		name string
		sub  *db.WorkspaceSubscription
		want string
	}{
		{
			"active flex",
			&db.WorkspaceSubscription{Plan: PlanFlex, Status: string(StatusActive)},
			PlanFlex,
		},
		{
			"trialing community",
			&db.WorkspaceSubscription{Plan: PlanCommunity, Status: string(StatusTrialing)},
			PlanCommunity,
		},
		{
			"past due keeps plan",
			&db.WorkspaceSubscription{Plan: PlanEnterprise, Status: string(StatusPastDue)},
			PlanEnterprise,
		},
		{
			"inactive falls back to community",
			&db.WorkspaceSubscription{Plan: PlanEnterprise, Status: string(StatusInactive)},
			PlanCommunity,
		},
		{
			"unknown status fails closed",
			&db.WorkspaceSubscription{Plan: PlanFlex, Status: "weird"},
			PlanCommunity,
		},
		{
			"empty status fails closed",
			&db.WorkspaceSubscription{Plan: PlanFlex, Status: ""},
			PlanCommunity,
		},
		{
			"missing subscription falls back to community",
			nil,
			PlanCommunity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wsID := seedWorkspace(t, conn, tt.sub)
			svc := NewPolicyService(conn, fakeLicenser{valid: false})

			plan := svc.Resolve(context.Background(), wsID)
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

func TestService_Resolve_FailsClosedOnDBError(t *testing.T) {
	conn := testConnection(t)
	wsID := seedWorkspace(t, conn, &db.WorkspaceSubscription{
		Plan: PlanFlex, Status: string(StatusActive),
	})
	svc := NewPolicyService(conn, fakeLicenser{valid: false})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	plan := svc.Resolve(ctx, wsID)
	if plan.Name != PlanCommunity {
		t.Errorf("Resolve() on DB error = %q, want community", plan.Name)
	}
}

func TestFlexIncludesSSOFeatures(t *testing.T) {
	conn := testConnection(t)
	wsID := seedWorkspace(t, conn, &db.WorkspaceSubscription{
		Plan: PlanFlex, Status: string(StatusActive),
	})
	svc := NewPolicyService(conn, fakeLicenser{valid: false})

	ctx := context.Background()
	for _, feature := range []string{FeatureOIDC, FeatureSAML, FeatureEnforceSSO} {
		if !svc.Has(ctx, wsID, feature) {
			t.Errorf("Flex should include %s", feature)
		}
	}
}

func TestService_Has_And_Int(t *testing.T) {
	conn := testConnection(t)
	wsID := seedWorkspace(t, conn, nil)
	svc := NewPolicyService(conn, fakeLicenser{valid: false})
	ctx := context.Background()

	// No subscription row => community plan.
	if svc.Has(ctx, wsID, FeatureEnforceSSO) {
		t.Error("community must not have enforce_sso")
	}
	if got := svc.Int(ctx, wsID, ValueAuditRetentionDays, 999); got != 7 {
		t.Errorf("community retention = %d, want 7", got)
	}
	if got := svc.Int(ctx, wsID, "unknown_key", 42); got != 42 {
		t.Errorf("unknown value fallback = %d, want 42", got)
	}
}

func TestService_Has_OnLicensedInstance(t *testing.T) {
	svc := NewPolicyService(testConnection(t), fakeLicenser{valid: true})
	if !svc.Has(context.Background(), "ws-1", FeatureEnforceSSO) {
		t.Error("licensed instance must have enforce_sso")
	}
}

func TestService_Check_QuotaExceeded(t *testing.T) {
	conn := testConnection(t)
	// CreateWorkspace already adds the owner, so four extra members reach the
	// community hard cap of five.
	wsID := seedWorkspace(t, conn, &db.WorkspaceSubscription{
		Plan: PlanCommunity, Status: string(StatusActive),
	})
	addMembers(t, conn, wsID, 4)
	svc := NewPolicyService(conn, fakeLicenser{valid: false})

	err := svc.Check(context.Background(), wsID, ResourceMembers)
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
	conn := testConnection(t)
	wsID := seedWorkspace(t, conn, &db.WorkspaceSubscription{
		Plan: PlanCommunity, Status: string(StatusActive),
	})
	addMembers(t, conn, wsID, 3)
	svc := NewPolicyService(conn, fakeLicenser{valid: false})

	if err := svc.Check(context.Background(), wsID, ResourceMembers); err != nil {
		t.Errorf("Check() under cap: %v", err)
	}
}

func TestService_Check_FailsClosedOnStatsError(t *testing.T) {
	conn := testConnection(t)

	tests := []struct {
		name     string
		sub      *db.WorkspaceSubscription
		resource Resource
		cancel   bool
		wantErr  bool
	}{
		{
			"stats db error",
			&db.WorkspaceSubscription{Plan: PlanCommunity, Status: string(StatusActive)},
			ResourceMembers,
			true,
			true,
		},
		{
			"unlimited plan",
			&db.WorkspaceSubscription{Plan: PlanFlex, Status: string(StatusActive)},
			ResourceMembers,
			false,
			false,
		},
		{
			"unknown resource",
			&db.WorkspaceSubscription{Plan: PlanCommunity, Status: string(StatusActive)},
			Resource("bogus"),
			false,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wsID := seedWorkspace(t, conn, tt.sub)
			svc := NewPolicyService(conn, fakeLicenser{valid: false})

			ctx := context.Background()
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			err := svc.Check(ctx, wsID, tt.resource)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}
