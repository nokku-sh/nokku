package entitlement

import (
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/core/internal/actor"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	nokkuv1connect "github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
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

// conditionalFeatures is kept in sync by hand with requestedFeatures, the golden test fails when it drifts.
func conditionalFeatures() []string {
	return []string{
		FeatureEnforceSSO, FeatureExpiringAccess, FeatureIdleTimeout, FeatureAccessRequests, FeatureAuditStreaming,
	}
}

// featuresFreeInAllPlans need no gate. Making one paid means wiring it in the guard in the same change.
var featuresFreeInAllPlans = []string{FeatureOIDC}

// A paid feature that no route enforces is revenue leakage, a feature no plan includes is dead weight.
func TestGolden_FeaturesWired(t *testing.T) {
	for _, f := range CatalogFeatures {
		if wiredFeatures()[f.Code] || slices.Contains(featuresFreeInAllPlans, f.Code) {
			continue
		}
		t.Errorf(
			"feature %q is in the catalog but gated nowhere: wire it in procedureFeatures/requestedFeatures or list it as free",
			f.Code,
		)
	}

	// The reverse direction: gates must reference real catalog features.
	for feature := range wiredFeatures() {
		if !slices.ContainsFunc(CatalogFeatures, func(f Feature) bool { return f.Code == feature }) {
			t.Errorf("guard gates %q, which is not a catalog feature", feature)
		}
	}
}

func TestRequestedFeatures(t *testing.T) {
	tests := []struct {
		name string
		msg  any
		want []string
	}{
		{
			name: "enforcing SSO is gated",
			msg:  &nokkuv1.UpdateWorkspaceRequest{Settings: &nokkuv1.WorkspaceSettings{EnforceSso: new(true)}},
			want: []string{FeatureEnforceSSO},
		},
		{
			name: "relaxing SSO is never gated",
			msg:  &nokkuv1.UpdateWorkspaceRequest{Settings: &nokkuv1.WorkspaceSettings{EnforceSso: new(false)}},
		},
		{
			name: "other workspace updates are not gated",
			msg:  &nokkuv1.UpdateWorkspaceRequest{Name: new("renamed"), Settings: &nokkuv1.WorkspaceSettings{}},
		},
		{
			name: "an idle timeout is gated",
			msg: &nokkuv1.UpdateWorkspaceRequest{
				Settings: &nokkuv1.WorkspaceSettings{SessionIdleTimeout: durationpb.New(15 * time.Minute)},
			},
			want: []string{FeatureIdleTimeout},
		},
		{
			name: "turning the idle timeout off is never gated",
			msg: &nokkuv1.UpdateWorkspaceRequest{
				Settings: &nokkuv1.WorkspaceSettings{SessionIdleTimeout: durationpb.New(0)},
			},
		},
		{
			name: "both settings at once are both checked",
			msg: &nokkuv1.UpdateWorkspaceRequest{
				Settings: &nokkuv1.WorkspaceSettings{
					EnforceSso:         new(true),
					SessionIdleTimeout: durationpb.New(time.Minute),
				},
			},
			want: []string{FeatureEnforceSSO, FeatureIdleTimeout},
		},
		{
			name: "a grant that ends is gated",
			msg:  &nokkuv1.AddSubjectsRequest{ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))},
			want: []string{FeatureExpiringAccess},
		},
		{
			name: "a grant for good is never gated",
			msg:  &nokkuv1.AddSubjectsRequest{},
		},
		{
			name: "opening targets to requests is gated",
			msg:  &nokkuv1.SetRequestableTagsRequest{Tags: []string{"prod"}},
			want: []string{FeatureAccessRequests},
		},
		{
			name: "closing them is never gated",
			msg:  &nokkuv1.SetRequestableTagsRequest{},
		},
		{
			name: "turning a stream on is gated",
			msg:  &nokkuv1.UpdateAuditStreamRequest{Enabled: new(true)},
			want: []string{FeatureAuditStreaming},
		},
		{
			name: "turning it off is never gated",
			msg:  &nokkuv1.UpdateAuditStreamRequest{Enabled: new(false)},
		},
		{
			name: "a message of another type is ignored",
			msg:  "not a proto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, requestedFeatures(tt.msg))
		})
	}
}

func TestGuard_DeniesAFeatureThePlanLacks(t *testing.T) {
	sut := selfHosted(t)
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: "ws1"})

	err := sut.checkFeature(ctx, nokkuv1connect.UtilServiceExportAuditLogsProcedure, struct{}{})

	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.ErrorContains(t, err, "audit log export is not available on the Community plan")
}

func TestGuard_AllowsPaidPlanAndUnpinnedContext(t *testing.T) {
	pinned := actor.WithWorkspace(t.Context(), actor.Workspace{ID: "ws1"})

	licensed := selfHosted(t, issue(t, PlanEnterprise, time.Hour))
	require.NoError(t, licensed.checkFeature(pinned, nokkuv1connect.UtilServiceExportAuditLogsProcedure, struct{}{}))

	// The authz interceptor owns that boundary.
	community := selfHosted(t)
	require.NoError(
		t,
		community.checkFeature(t.Context(), nokkuv1connect.UtilServiceExportAuditLogsProcedure, struct{}{}),
		"an unpinned context must pass",
	)
	assert.NoError(t, community.checkFeature(pinned, "/nokku.v1.UtilService/GetVersion", struct{}{}),
		"an ungated procedure must pass")
}

// createProcedures is kept in sync by hand, the golden test fails when it drifts from cappedCreate.
var createProcedures = []string{
	nokkuv1connect.TargetServiceCreateTargetProcedure,
	nokkuv1connect.TeamServiceCreateTeamProcedure,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure,
	nokkuv1connect.CertificateServiceCreateCertificateAuthorityProcedure,
	nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure,
	nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure,
	nokkuv1connect.DaemonServiceCreateSessionProcedure,
	nokkuv1connect.LegalHoldServiceCreateLegalHoldProcedure,
	nokkuv1connect.AccessRequestServiceCreateAccessRequestProcedure,
	nokkuv1connect.AuditStreamServiceCreateAuditStreamProcedure,
}

// createProceduresGatedOutsideTheGuard have their quota check elsewhere, with the place named.
var createProceduresGatedOutsideTheGuard = map[string]string{
	// Enrollment is public and its workspace comes from the enroll token, the handler checks the cap.
	nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure: "handler: CheckResources in EnrollDaemon (public endpoint, workspace from token)",
	// Pre-tenant: the hosted signup makes the workspace a cap would be resolved for.
	nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure: "pre-tenant: bounded by the auth rate limit",
	// Sessions are bounded by the recording storage cap and eviction, they leave no permanent rows.
	nokkuv1connect.DaemonServiceCreateSessionProcedure: "bounded by recording storage eviction",
	// Each hold also weighs on every retention delete.
	nokkuv1connect.LegalHoldServiceCreateLegalHoldProcedure: "handler: maxLegalHolds per workspace",
	// Asking and cancelling over and over would leave a row each time.
	nokkuv1connect.AccessRequestServiceCreateAccessRequestProcedure: "handler: maxDailyRequests per person",
	nokkuv1connect.AuditStreamServiceCreateAuditStreamProcedure:     "handler: maxAuditStreams per workspace",
}

// An uncapped create route on SaaS is an unbounded-resource hole, so each is capped or exempted with a reason.
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
