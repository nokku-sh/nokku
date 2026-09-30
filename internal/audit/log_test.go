package audit

import (
	"testing"

	"google.golang.org/protobuf/proto"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
)

func TestNewEventSkipsReads(t *testing.T) {
	tests := []struct {
		procedure string
		audited   bool
	}{
		{"/nokku.v1.TargetService/DeleteTarget", true},
		{"/nokku.v1.CertificateService/SignSSHCertificate", true},
		{"/nokku.v1.FutureService/FrobnicateThing", true},
		{"/nokku.v1.TargetService/GetTarget", false},
		{"/nokku.v1.TargetService/ListTargets", false},
		{"/nokku.v1.TargetService/SyncTargetUsers", false},
		{"/nokku.v1.DaemonControlService/Connect", false},
	}
	for _, tt := range tests {
		e := newEvent(tt.procedure)
		if (e != nil) != tt.audited {
			t.Errorf("%s audited = %v, want %v", tt.procedure, e != nil, tt.audited)
		}
	}
	if e := newEvent("/nokku.v1.TargetService/DeleteTarget"); e.Action != "DeleteTarget" {
		t.Errorf("action = %q, want DeleteTarget", e.Action)
	}
}

func TestRequestTarget(t *testing.T) {
	tests := []struct {
		msg  proto.Message
		want string
	}{
		{&nokkuv1.DeleteTargetRequest{WorkspaceId: new("ws"), Id: new("t1")}, "t1"},
		{&nokkuv1.CreateTargetRequest{WorkspaceId: new("ws"), CaId: new("ca"), Name: new("web")}, "web"},
		{&nokkuv1.UpdateWorkspaceMemberRequest{WorkspaceId: new("ws"), UserId: new("u1")}, "u1"},
		{&nokkuv1.DeleteWorkspaceRequest{WorkspaceId: new("ws")}, ""},
		{&nokkuv1.ChangePasswordRequest{CurrentPassword: new("old"), NewPassword: new("new")}, ""},
	}
	for _, tt := range tests {
		if got := requestTarget(tt.msg.ProtoReflect()); got != tt.want {
			t.Errorf("%T target = %q, want %q", tt.msg, got, tt.want)
		}
	}
}
