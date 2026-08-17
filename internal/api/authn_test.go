package api

import (
	"context"
	"testing"

	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/meta"
)

func TestActorType(t *testing.T) {
	cases := []struct {
		kind kagi.Kind
		want meta.ActorType
	}{
		{kagi.KindUser, meta.ActorTypeUser},
		{auth.KindDaemon, meta.ActorTypeDaemon},
		{auth.KindServiceAccount, meta.ActorTypeServiceAccount},
		{auth.KindDevice, meta.ActorTypeUser},
	}
	for _, c := range cases {
		if got := actorType(c.kind); got != c.want {
			t.Errorf("actorType(%q) = %q, want %q", c.kind, got, c.want)
		}
	}
}

func TestWithActorUserPrincipal(t *testing.T) {
	ctx := applyPrincipal(context.Background(), kagi.Principal{
		SubjectID: "user-1",
		Kind:      kagi.KindUser,
	}, nil)

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
		Kind:      auth.KindDaemon,
		TenantID:  "ws-1",
	}, nil)

	actor := meta.ActorFromContext(ctx)
	if actor.ID != "daemon-1" || actor.Type != meta.ActorTypeDaemon {
		t.Fatalf("unexpected actor: %+v", actor)
	}
	if ws := meta.WorkspaceIDFromContext(ctx); ws != "ws-1" {
		t.Fatalf("expected pinned workspace ws-1, got %q", ws)
	}
}
