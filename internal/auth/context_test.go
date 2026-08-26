package auth

import (
	"context"
	"testing"

	"github.com/mizuchilabs/kagi"
)

func TestUserIDFromContext(t *testing.T) {
	ctx := kagi.ContextWithPrincipal(context.Background(), kagi.Principal{
		SubjectID: "user-1",
		Kind:      kagi.KindUser,
	})
	if id := UserIDFromContext(ctx); id != "user-1" {
		t.Fatalf("expected user-1, got %q", id)
	}

	device := kagi.ContextWithPrincipal(context.Background(), kagi.Principal{
		SubjectID: "user-1",
		Kind:      ActorTypeDevice,
	})
	if id := UserIDFromContext(device); id != "user-1" {
		t.Fatalf("expected user-1 for device session, got %q", id)
	}
}

func TestDaemonIDFromContext(t *testing.T) {
	ctx := kagi.ContextWithPrincipal(context.Background(), kagi.Principal{
		SubjectID: "daemon-1",
		Kind:      ActorTypeDaemon,
		TenantID:  "ws-1",
	})
	if id := DaemonIDFromContext(ctx); id != "daemon-1" {
		t.Fatalf("expected daemon-1, got %q", id)
	}
	if id := UserIDFromContext(ctx); id != "" {
		t.Fatalf("expected empty user id for daemon principal, got %q", id)
	}
}

func TestWorkspaceIDFromContext(t *testing.T) {
	machine := kagi.ContextWithPrincipal(context.Background(), kagi.Principal{
		SubjectID: "daemon-1",
		Kind:      ActorTypeDaemon,
		TenantID:  "ws-1",
	})
	if ws := WorkspaceIDFromContext(machine); ws != "ws-1" {
		t.Fatalf("expected machine tenant ws-1, got %q", ws)
	}

	user := kagi.ContextWithPrincipal(context.Background(), kagi.Principal{
		SubjectID: "user-1",
		Kind:      kagi.KindUser,
	})
	kagi.AnnotateTenant(user, "ws-2")
	if ws := WorkspaceIDFromContext(user); ws != "ws-2" {
		t.Fatalf("expected resolved tenant ws-2, got %q", ws)
	}
}
