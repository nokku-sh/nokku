package entitlement

import (
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/core/internal/actor"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

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
			msg:  &nokkuv1.UpdateDaemonDefaultsRequest{SessionIdleTimeout: durationpb.New(15 * time.Minute)},
			want: []string{FeatureIdleTimeout},
		},
		{
			name: "turning the idle timeout off is never gated",
			msg:  &nokkuv1.UpdateDaemonDefaultsRequest{SessionIdleTimeout: durationpb.New(0)},
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
			assert.Equal(t, tt.want, RequestedFeatures(tt.msg))
		})
	}
}

func TestCheckFeaturesDeniesAFeatureThePlanLacks(t *testing.T) {
	sut := selfHosted(t)
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: "ws1"})

	err := sut.CheckFeatures(ctx, []string{FeatureAuditExport})

	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.ErrorContains(t, err, "Audit log export is not available on the Community plan")
}

func TestCheckFeaturesAllowsPaidPlanAndUnpinnedContext(t *testing.T) {
	pinned := actor.WithWorkspace(t.Context(), actor.Workspace{ID: "ws1"})

	licensed := selfHosted(t, issue(t, PlanEnterprise, time.Hour))
	require.NoError(t, licensed.CheckFeatures(pinned, []string{FeatureAuditExport}))

	// The authz interceptor owns that boundary.
	community := selfHosted(t)
	require.NoError(
		t,
		community.CheckFeatures(t.Context(), []string{FeatureAuditExport}),
		"an unpinned context must pass",
	)
	assert.NoError(t, community.CheckFeatures(pinned, nil), "a call that needs no feature must pass")
}
