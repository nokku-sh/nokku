package audit

import (
	"testing"
	"time"

	"github.com/mizuchilabs/kagi"
)

func TestEventFromKagi(t *testing.T) {
	ts := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	ev := eventFromKagi(kagi.Event{
		TenantID: kagi.TenantID("ws-1"),
		UserID:   "user-1",
		Email:    "user-1@example.com",
		Kind:     kagi.KindUser,
		Method:   kagi.MethodPassword,
		Action:   kagi.ActionLoginSuccess,
		Provider: "google",
		Detail:   "ok",
		Time:     ts,
	})

	if ev.WorkspaceID != "ws-1" {
		t.Errorf("WorkspaceID = %q, want ws-1", ev.WorkspaceID)
	}
	if ev.ActorID != "user-1" || ev.ActorType != "user" {
		t.Errorf("actor = %q/%q, want user-1/user", ev.ActorID, ev.ActorType)
	}
	if ev.ActorEmail != "user-1@example.com" {
		t.Errorf("ActorEmail = %q, want user-1@example.com", ev.ActorEmail)
	}
	if ev.Action != "login_success" {
		t.Errorf("Action = %q, want login_success", ev.Action)
	}
	if ev.StatusCode != "OK" {
		t.Errorf("StatusCode = %q, want OK", ev.StatusCode)
	}
	if ev.Details["method"] != "password" ||
		ev.Details["provider"] != "google" ||
		ev.Details["detail"] != "ok" {
		t.Errorf("Details = %v", ev.Details)
	}
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, ts)
	}
}

func TestEventFromKagi_Unresolved(t *testing.T) {
	ev := eventFromKagi(kagi.Event{Action: kagi.ActionLoginDenied})
	if ev.ActorID != "" || ev.ActorType != "" || ev.ActorEmail != "" {
		t.Errorf("actor fields = %q/%q/%q, want empty",
			ev.ActorID, ev.ActorType, ev.ActorEmail)
	}
	if ev.WorkspaceID != "" {
		t.Errorf("WorkspaceID = %q, want empty", ev.WorkspaceID)
	}
	if ev.StatusCode != "denied" {
		t.Errorf("StatusCode = %q, want denied", ev.StatusCode)
	}
	if ev.Timestamp.IsZero() {
		t.Errorf("Timestamp should default to now")
	}
}

func TestShouldAuditMutatingOnly(t *testing.T) {
	tests := []struct {
		name      string
		procedure string
		want      bool
	}{
		{name: "create rpc", procedure: "/nokku.v1.WorkspaceService/CreateWorkspace", want: true},
		{name: "post http", procedure: "POST /upload/avatar", want: true},
		{name: "get http", procedure: "GET /avatars/id", want: false},
		{name: "read rpc", procedure: "/nokku.v1.WorkspaceService/GetWorkspace", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldAudit(tt.procedure); got != tt.want {
				t.Fatalf("shouldAudit(%q) = %v, want %v", tt.procedure, got, tt.want)
			}
		})
	}
}
