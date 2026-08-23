package audit

import (
	"context"
	"testing"
	"time"

	"github.com/mizuchilabs/kagi"
)

func TestEventFromKagi(t *testing.T) {
	ts := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	ev := eventFromKagi(kagi.Event{
		TenantID: kagi.TenantID("ws-1"),
		UserID:   "user-1",
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
	if ev.Action != "login_success" {
		t.Errorf("Action = %q, want login_success", ev.Action)
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

func TestEventFromKagi_Anonymous(t *testing.T) {
	ev := eventFromKagi(kagi.Event{Action: kagi.ActionLoginDenied})
	if ev.ActorID != anonActorID {
		t.Errorf("ActorID = %q, want anon", ev.ActorID)
	}
	if ev.ActorType != "anonymous" {
		t.Errorf("ActorType = %q, want anonymous", ev.ActorType)
	}
	if ev.WorkspaceID != "" {
		t.Errorf("WorkspaceID = %q, want empty", ev.WorkspaceID)
	}
	if ev.Timestamp.IsZero() {
		t.Errorf("Timestamp should default to now")
	}
}

func TestWorkspaceIDFromContext_MachinePrincipal(t *testing.T) {
	ctx := kagi.WithPrincipal(context.Background(), kagi.Principal{
		SubjectID: "daemon-1",
		TenantID:  kagi.TenantID("ws-daemon"),
		Kind:      "daemon",
	})
	if got := WorkspaceIDFromContext(ctx); got != "ws-daemon" {
		t.Errorf("WorkspaceIDFromContext = %q, want ws-daemon", got)
	}
}

func TestWorkspaceIDFromContext_UserTenant(t *testing.T) {
	ctx := kagi.WithTenant(context.Background(), kagi.TenantID("ws-req"))
	if got := WorkspaceIDFromContext(ctx); got != "ws-req" {
		t.Errorf("WorkspaceIDFromContext = %q, want ws-req", got)
	}
}

func TestWorkspaceIDFromContext_Empty(t *testing.T) {
	if got := WorkspaceIDFromContext(context.Background()); got != "" {
		t.Errorf("WorkspaceIDFromContext = %q, want empty", got)
	}
}
