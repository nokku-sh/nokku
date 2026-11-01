package audit

import (
	"testing"

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
		if err != nil {
			t.Fatalf("%s: %v", tt.method, err)
		}
		if got := Records(d); got != tt.audited {
			t.Errorf("%s audited = %v, want %v", tt.method, got, tt.audited)
		}
	}
	if !Records(nil) {
		t.Error("a call without a schema was skipped")
	}
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
		if got := requestTarget(tt.msg.ProtoReflect()); got != tt.want {
			t.Errorf("%T target = %q, want %q", tt.msg, got, tt.want)
		}
	}
}
