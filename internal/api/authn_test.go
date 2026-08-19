package api

import (
	"context"
	"testing"

	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/meta"
)

func TestWithActorUserPrincipal(t *testing.T) {
	ctx := applyPrincipal(context.Background(), kagi.Principal{
		SubjectID: "user-1",
		Kind:      kagi.KindUser,
	})

	actor := meta.ActorFromContext(ctx)
	if actor.ID != "user-1" || actor.Type != meta.ActorTypeUser {
		t.Fatalf("unexpected actor: %+v", actor)
	}
	if ws := meta.WorkspaceIDFromContext(ctx); ws != "" {
		t.Fatalf("expected no pinned workspace for a global user, got %q", ws)
	}
}

func TestWithActorDaemonPrincipalPinsWorkspace(t *testing.T) {
	ctx := applyPrincipal(context.Background(), kagi.Principal{
		SubjectID: "daemon-1",
		Kind:      meta.ActorTypeDaemon,
		TenantID:  "ws-1",
	})

	actor := meta.ActorFromContext(ctx)
	if actor.ID != "daemon-1" || actor.Type != meta.ActorTypeDaemon {
		t.Fatalf("unexpected actor: %+v", actor)
	}
	if ws := meta.WorkspaceIDFromContext(ctx); ws != "ws-1" {
		t.Fatalf("expected pinned workspace ws-1, got %q", ws)
	}
}
