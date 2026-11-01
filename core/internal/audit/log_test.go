package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

func TestRecordsSkipsReadsAndQuietCalls(t *testing.T) {
	tests := []struct {
		method  protoreflect.FullName
		audited bool
	}{
		{"nokku.v1.TargetService.DeleteTarget", true},
		{"nokku.v1.CertificateService.SignSSHCertificate", true},
		{"nokku.v1.TargetService.SyncTargetUsers", true},
		{"nokku.v1.DaemonControlService.UploadRecording", true},
		{"nokku.v1.TargetService.GetTarget", false},
		{"nokku.v1.TargetService.ListTargets", false},
		{"nokku.v1.RecordingService.GetRecording", false},
		{"nokku.v1.DaemonControlService.SyncDaemon", false},
		{"nokku.v1.DaemonControlService.Connect", false},
		{"nokku.v1.DaemonService.Relay", false},
	}
	for _, tt := range tests {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(tt.method)
		require.NoError(t, err, "%s", tt.method)
		assert.Equal(t, tt.audited, Records(d), "%s audited", tt.method)
	}
	assert.True(t, Records(nil), "a call without a schema was skipped")
}

func TestRequestTarget(t *testing.T) {
	tests := []struct {
		msg  proto.Message
		want string
	}{
		{&nokkuv1.DeleteTargetRequest{Id: new("t1")}, "t1"},
		{&nokkuv1.CreateTargetRequest{Name: new("web")}, "web"},
		{
			&nokkuv1.UpdateUserRoleRequest{UserId: new("u1"), Role: new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)},
			"u1",
		},
		{&nokkuv1.DeleteWorkspaceRequest{}, ""},
		{&nokkuv1.ConsumeMagicLinkRequest{Token: new("secret")}, ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, requestTarget(tt.msg.ProtoReflect()), "%T target", tt.msg)
	}
}
