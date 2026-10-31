package api

import (
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

func TestApplyMaskKeepsOnlyNamedFields(t *testing.T) {
	req := &nokkuv1.UpdateTargetRequest{
		Id:          new("t1"),
		Name:        new("renamed"),
		Description: new("stale copy from the form"),
		Tags:        []string{"stale"},
		UpdateMask:  &fieldmaskpb.FieldMask{Paths: []string{"name", "endpoints"}},
	}
	named, err := applyMask(req, req.GetUpdateMask())
	require.NoError(t, err)

	assert.Equal(t, "t1", req.GetId(), "the id is never masked away")
	assert.Equal(t, "renamed", req.GetName())
	assert.Nil(t, req.Description, "a field the mask does not name was kept")
	assert.Nil(t, req.GetTags())
	assert.True(t, named("endpoints"), "a named list counts even when empty")
	assert.False(t, named("tags"))
}

func TestMaskedList(t *testing.T) {
	assert.Nil(t, maskedList(false, []string{"a"}), "a list the mask does not name was written")
	empty := maskedList(true, nil)
	assert.NotNil(t, empty, "a named empty list would keep the stored one")
	assert.Empty(t, empty)
}

func TestApplyMaskRefusesANamedFieldItDoesNotSend(t *testing.T) {
	req := &nokkuv1.UpdateTeamRequest{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name"}}}
	_, err := applyMask(req, req.GetUpdateMask())
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "an unchecked empty name would be stored")
}

func TestApplyMaskPrunesNestedMessages(t *testing.T) {
	req := &nokkuv1.UpdateWorkspaceRequest{
		Settings: &nokkuv1.WorkspaceSettings{
			EnforceSso:          new(true),
			DefaultDaemonConfig: &nokkuv1.DaemonConfig{RecordSessions: new(true), GatewayPorts: new(true)},
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"settings.default_daemon_config.gateway_ports"}},
	}
	_, err := applyMask(req, req.GetUpdateMask())
	require.NoError(t, err)
	assert.Nil(t, req.GetSettings().EnforceSso)
	assert.Nil(t, req.GetSettings().GetDefaultDaemonConfig().RecordSessions)
	assert.True(t, req.GetSettings().GetDefaultDaemonConfig().GetGatewayPorts())
}

func TestMergeSetReplacesADurationWhole(t *testing.T) {
	stored := &nokkuv1.WorkspaceSettings{
		SessionIdleTimeout:  durationpb.New(15 * time.Minute),
		DefaultDaemonConfig: &nokkuv1.DaemonConfig{RecordSessions: new(true), AllowForwarding: new(true)},
	}
	mergeSet(stored.ProtoReflect(), (&nokkuv1.WorkspaceSettings{
		SessionIdleTimeout:  durationpb.New(0),
		DefaultDaemonConfig: &nokkuv1.DaemonConfig{AllowForwarding: new(false)},
	}).ProtoReflect())

	assert.Zero(t, stored.GetSessionIdleTimeout().AsDuration(), "a zero timeout must turn it off")
	assert.True(t, stored.GetDefaultDaemonConfig().GetRecordSessions(), "a field the update left out was lost")
	assert.False(t, stored.GetDefaultDaemonConfig().GetAllowForwarding())
}

// A mask may only reach into our own messages. Past a scalar, a list or a Duration there is nothing to name, and the
// stored value would differ from what the plan gates saw.
func TestApplyMaskRefusesAPathPastAField(t *testing.T) {
	for _, tt := range []struct {
		req  proto.Message
		mask string
	}{
		{&nokkuv1.UpdateTeamRequest{Name: new("ops")}, "name.x"},
		{&nokkuv1.UpdateTeamRequest{Tags: []string{"a"}}, "tags.x"},
		{&nokkuv1.UpdateWorkspaceRequest{Settings: &nokkuv1.WorkspaceSettings{
			SessionIdleTimeout: &durationpb.Duration{Seconds: 2, Nanos: -2e9},
		}}, "settings.session_idle_timeout.seconds"},
	} {
		_, err := applyMask(tt.req, &fieldmaskpb.FieldMask{Paths: []string{tt.mask}})
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), tt.mask)
	}
}
