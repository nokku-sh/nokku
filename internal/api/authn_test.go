package api

import (
	"context"
	"testing"

	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
)

func TestWithRequestWorkspace(t *testing.T) {
	workspaceID := "00000000-0000-0000-0000-000000000001"
	ctx := withRequestWorkspace(context.Background(), &nokkuv1.GetTargetRequest{
		WorkspaceId: &workspaceID,
	})

	if got, ok := meta.WorkspaceIDFromContext(ctx); !ok || got != workspaceID {
		t.Fatalf("workspace context = %q, %v; want %q, true", got, ok, workspaceID)
	}
}

func TestWithRequestWorkspaceWithoutField(t *testing.T) {
	ctx := withRequestWorkspace(context.Background(), &nokkuv1.LoginRequest{})

	if _, ok := meta.WorkspaceIDFromContext(ctx); ok {
		t.Fatal("workspace context unexpectedly set for global request")
	}
}
