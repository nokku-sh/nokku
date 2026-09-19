package entitlement

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/actor"

	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	nokkuv1connect "github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
)

// wiredFeatures lists every feature gated somewhere in the guard.
func wiredFeatures() map[string]bool {
	wired := make(map[string]bool)
	for _, feature := range procedureFeatures {
		wired[feature] = true
	}
	for _, feature := range conditionalFeatures() {
		wired[feature] = true
	}
	return wired
}

// conditionalFeatures returns the features checked inside
// conditionalFeature. Kept in sync manually; the golden test below fails
// when the switch and this list drift apart.
func conditionalFeatures() []string {
	return []string{FeatureSAML, FeatureEnforceSSO, FeatureAuditStreaming}
}

// featuresFreeInAllPlans are catalog features that need no gate because
// every plan includes them. Removing a feature from this list (making it
// paid) requires wiring it in the guard in the same change.
var featuresFreeInAllPlans = []string{FeatureOIDC}

// featuresGatedOutsideTheGuard are catalog features enforced elsewhere,
// with the enforcement point documented. External KMS is instance-level
// configuration (KMS_URI requires a valid license), not a per-workspace
// route, so the guard cannot gate it.
var featuresGatedOutsideTheGuard = map[string]string{
	FeatureExternalKMS: "instance-level: KMS_URI startup check in internal/config",
}

// TestGolden_FeaturesWired fails whenever someone adds a catalog feature
// without wiring it (or explicitly exempting it). A paid feature that no
// route enforces is revenue leakage; a feature no plan includes is dead
// catalog weight.
func TestGolden_FeaturesWired(t *testing.T) {
	allFeatures := CatalogFeatures

	for _, f := range allFeatures {
		feature := f.Code
		reason := "unwired"
		switch {
		case wiredFeatures()[feature]:
			continue
		case slices.Contains(featuresFreeInAllPlans, feature):
			reason = "free in all plans"
		default:
			if _, ok := featuresGatedOutsideTheGuard[feature]; ok {
				reason = "gated outside the guard"
			}
		}
		if reason == "unwired" {
			t.Errorf(
				"feature %q is in the catalog but gated nowhere: wire it in procedureFeatures/conditionalFeature or exempt it with a documented reason",
				feature,
			)
		}
	}

	// The reverse direction: gates must reference real catalog features.
	for feature := range wiredFeatures() {
		if _, ok := featureInCatalog(feature); !ok {
			t.Errorf("guard gates %q, which is not a catalog feature", feature)
		}
	}
}

func TestConditionalFeature(t *testing.T) {
	samlActivate := &nokkuv1.UpdateSSOProviderRequest{
		Method:   new("saml"),
		IsActive: new(true),
	}
	samlDeactivate := &nokkuv1.UpdateSSOProviderRequest{Method: new("saml")}
	oidcEnforce := &nokkuv1.UpdateSSOProviderRequest{
		Method:     new("oidc"),
		EnforceSso: new(true),
	}
	oidcPlain := &nokkuv1.UpdateSSOProviderRequest{Method: new("oidc")}

	streamingOn := &nokkuv1.UpdateWorkspaceRequest{
		Settings: &nokkuv1.WorkspaceSettings{
			AuditWebhookUrl: new("https://hooks.example.com/nokku"),
		},
	}
	streamingSecretOnly := &nokkuv1.UpdateWorkspaceRequest{
		Settings: &nokkuv1.WorkspaceSettings{AuditWebhookSecret: new("s3cret")},
	}
	streamingOff := &nokkuv1.UpdateWorkspaceRequest{
		Name:     new("renamed"),
		Settings: &nokkuv1.WorkspaceSettings{AuditWebhookUrl: new("")},
	}
	workspacePlain := &nokkuv1.UpdateWorkspaceRequest{
		Name:     new("renamed"),
		Settings: &nokkuv1.WorkspaceSettings{},
	}

	tests := []struct {
		name      string
		procedure string
		msg       any
		wantFeat  string
		wantGated bool
	}{
		{
			name:      "activating SAML is gated",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       samlActivate,
			wantFeat:  FeatureSAML,
			wantGated: true,
		},
		{
			name:      "deactivating SAML is never gated",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       samlDeactivate,
		},
		{
			name:      "enforcing SSO on OIDC is gated",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       oidcEnforce,
			wantFeat:  FeatureEnforceSSO,
			wantGated: true,
		},
		{
			name:      "plain OIDC update is not gated",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       oidcPlain,
		},
		{
			name:      "other procedures are not conditionally gated",
			procedure: "/nokku.v1.SSOService/GetSSOProvider",
			msg:       samlActivate,
		},
		{
			name:      "configuring audit streaming is gated",
			procedure: "/nokku.v1.WorkspaceService/UpdateWorkspace",
			msg:       streamingOn,
			wantFeat:  FeatureAuditStreaming,
			wantGated: true,
		},
		{
			name:      "setting only the streaming secret is gated",
			procedure: "/nokku.v1.WorkspaceService/UpdateWorkspace",
			msg:       streamingSecretOnly,
			wantFeat:  FeatureAuditStreaming,
			wantGated: true,
		},
		{
			name:      "clearing audit streaming is never gated",
			procedure: "/nokku.v1.WorkspaceService/UpdateWorkspace",
			msg:       streamingOff,
		},
		{
			name:      "other workspace updates are not gated",
			procedure: "/nokku.v1.WorkspaceService/UpdateWorkspace",
			msg:       workspacePlain,
		},
		{
			name:      "non-SSO request types are ignored",
			procedure: "/nokku.v1.SSOService/UpdateSSOProvider",
			msg:       "not a proto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feature, gated := conditionalFeature(tt.procedure, tt.msg)
			if gated != tt.wantGated {
				t.Errorf("gated = %v, want %v", gated, tt.wantGated)
			}
			if feature != tt.wantFeat {
				t.Errorf("feature = %q, want %q", feature, tt.wantFeat)
			}
		})
	}
}

func TestGuard_DeniesAndAdvertisesUpgrade(t *testing.T) {
	// Community workspace: audit export must deny with upgrade metadata.
	sut := NewGuardInterceptor(NewService(
		&fakeDB{},
		"",
		ModeSaaS,
	))

	ctx := actor.AnnotateTenant(context.Background(), "ws1")
	err := sut.check(ctx, "/nokku.v1.UtilService/ExportAuditLogs", struct{}{})

	if err == nil {
		t.Fatal("expected denial for audit export on community")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected *connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodePermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", connectErr.Code())
	}
	if got := connectErr.Meta().Get("x-nokku-plan"); got != PlanCommunity {
		t.Errorf("x-nokku-plan = %q, want %q", got, PlanCommunity)
	}
	if got := connectErr.Meta().Get("x-nokku-feature"); got != FeatureAuditExport {
		t.Errorf("x-nokku-feature = %q, want %q", got, FeatureAuditExport)
	}
	if got := connectErr.Meta().Get("x-nokku-upgrade"); got != UpgradeURL {
		t.Errorf("x-nokku-upgrade = %q, want %q", got, UpgradeURL)
	}
	if !strings.Contains(connectErr.Message(), "audit log export") {
		t.Errorf("message %q should name the feature", connectErr.Message())
	}
}

func TestGuard_DeniesAuditStreamingOnCommunity(t *testing.T) {
	sut := NewGuardInterceptor(NewService(&fakeDB{}, "", ModeSaaS))
	ctx := actor.AnnotateTenant(context.Background(), "ws1")

	req := &nokkuv1.UpdateWorkspaceRequest{
		Settings: &nokkuv1.WorkspaceSettings{AuditWebhookUrl: new("https://hooks.example.com")},
	}
	err := sut.check(ctx, "/nokku.v1.WorkspaceService/UpdateWorkspace", req)
	if err == nil {
		t.Fatal("expected denial for audit streaming on community")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected *connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodePermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", connectErr.Code())
	}
	if got := connectErr.Meta().Get("x-nokku-feature"); got != FeatureAuditStreaming {
		t.Errorf("x-nokku-feature = %q, want %q", got, FeatureAuditStreaming)
	}

	// Clearing the destination stays possible on any plan.
	cleared := &nokkuv1.UpdateWorkspaceRequest{
		Settings: &nokkuv1.WorkspaceSettings{AuditWebhookUrl: new("")},
	}
	if err := sut.check(ctx, "/nokku.v1.WorkspaceService/UpdateWorkspace", cleared); err != nil {
		t.Errorf("clearing the destination was denied: %v", err)
	}
}

func TestGuard_AllowsPaidPlanAndUnpinnedContext(t *testing.T) {
	sut := NewGuardInterceptor(NewService(
		&fakeDB{plan: PlanPro, status: StatusActive},
		"",
		ModeSaaS,
	))

	// Pro workspace passes.
	ctx := actor.AnnotateTenant(context.Background(), "ws1")
	if err := sut.check(ctx, "/nokku.v1.UtilService/ExportAuditLogs", struct{}{}); err != nil {
		t.Errorf("pro workspace denied: %v", err)
	}

	// Unpinned context passes (the authz interceptor owns that boundary).
	if err := sut.check(context.Background(), "/nokku.v1.UtilService/ExportAuditLogs", struct{}{}); err != nil {
		t.Errorf("unpinned context denied: %v", err)
	}

	// Ungated procedures pass everywhere.
	if err := sut.check(ctx, "/nokku.v1.UtilService/GetVersion", struct{}{}); err != nil {
		t.Errorf("ungated procedure denied: %v", err)
	}
}

// createProcedures lists every create-style procedure in the API surface
// (Create* and Enroll* RPCs). Kept in sync manually; the golden test below
// fails when this list and the cappedCreate map drift apart. A new resource
// type must be added here in the same change that adds its RPC.
var createProcedures = []string{
	nokkuv1connect.TargetServiceCreateTargetProcedure,
	nokkuv1connect.TeamServiceCreateTeamProcedure,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure,
	nokkuv1connect.CertificateServiceCreateCertificateAuthorityProcedure,
	nokkuv1connect.WorkspaceDomainServiceCreateWorkspaceDomainProcedure,
	nokkuv1connect.DaemonServiceEnrollDaemonProcedure,
	nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure,
	nokkuv1connect.DaemonServiceCreateSessionProcedure,
}

// createProceduresGatedOutsideTheGuard are create procedures whose quota
// check happens elsewhere, with the enforcement point documented.
var createProceduresGatedOutsideTheGuard = map[string]string{
	// Enrollment is a public endpoint whose workspace comes from the
	// enroll token; the handler checks the cap directly (daemon.go).
	nokkuv1connect.DaemonServiceEnrollDaemonProcedure: "handler: CheckResources in EnrollDaemon (public endpoint, workspace from token)",
	// Pre-tenant: there is no workspace to resolve a cap for. Per-user
	// workspace count caps are separate scope, enforced in CreateWorkspace.
	nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure: "out of scope: per-user workspace caps",
	// Sessions are bounded by the recording storage cap and eviction
	// (recording/evict.go); they produce no permanent resource rows.
	nokkuv1connect.DaemonServiceCreateSessionProcedure: "bounded by recording storage eviction",
}

// TestGolden_CappedProceduresWired fails whenever a create-style procedure
// is neither resource-capped in the guard nor explicitly exempted. An
// uncapped create route on SaaS is an unbounded-resource hole; an exempted
// route without a documented reason is indistinguishable from a forgotten
// one.
func TestGolden_CappedProceduresWired(t *testing.T) {
	for _, procedure := range createProcedures {
		switch {
		case cappedCreate[procedure]:
			continue
		default:
			if _, ok := createProceduresGatedOutsideTheGuard[procedure]; ok {
				continue
			}
			t.Errorf(
				"create procedure %q is capped nowhere: wire it in cappedCreate or exempt it with a documented reason",
				procedure,
			)
		}
	}

	// The reverse direction: caps must reference real procedures.
	for procedure := range cappedCreate {
		if !slices.Contains(createProcedures, procedure) {
			t.Errorf("cappedCreate gates %q, which is not a known create procedure", procedure)
		}
	}
}

func TestGuard_ResourceCapDeniesAndAdvertisesUpgrade(t *testing.T) {
	// Community: 50-resource cap, fake reports 50 used.
	sut := NewGuardInterceptor(NewService(
		&fakeDB{resources: 50},
		"",
		ModeSaaS,
	))

	ctx := actor.AnnotateTenant(context.Background(), "ws1")
	err := sut.checkResources(ctx, "/nokku.v1.TargetService/CreateTarget")

	if err == nil {
		t.Fatal("expected denial at resource cap")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected *connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodeResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", connectErr.Code())
	}
	if got := connectErr.Meta().Get("x-nokku-plan"); got != PlanCommunity {
		t.Errorf("x-nokku-plan = %q, want %q", got, PlanCommunity)
	}
	if got := connectErr.Meta().Get("x-nokku-quota"); got != "resources" {
		t.Errorf("x-nokku-quota = %q, want %q", got, "resources")
	}
	if got := connectErr.Meta().Get("x-nokku-upgrade"); got != UpgradeURL {
		t.Errorf("x-nokku-upgrade = %q, want %q", got, UpgradeURL)
	}
}

func TestCheckResources(t *testing.T) {
	tests := []struct {
		name    string
		db      *fakeDB
		mode    Mode
		wantErr bool
	}{
		{
			name:    "below cap passes",
			db:      &fakeDB{resources: 10},
			mode:    ModeSaaS,
			wantErr: false,
		},
		{
			name:    "at cap denies",
			db:      &fakeDB{resources: 50},
			mode:    ModeSaaS,
			wantErr: true,
		},
		{
			name: "count lookup fails open",
			db:   &fakeDB{resourceErr: errors.New("db down")},
			mode: ModeSaaS,
		},
		{
			name: "self-hosted is never capped",
			db:   &fakeDB{resources: 1 << 20},
			mode: ModeSelfHosted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sut := NewService(tt.db, "", tt.mode)
			err := sut.CheckResources(context.Background(), "ws1")
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckResources() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
