// Package meta provides context helpers
package meta

import (
	"context"
)

type (
	ctxKey    string
	ActorType string
)

const (
	ActorKey      ctxKey = "actor"
	AuditStateKey ctxKey = "audit"
	WorkspaceKey  ctxKey = "workspace"
	// ActorTypeUser identifies a human user actor.
	ActorTypeUser           ActorType = "user"
	ActorTypeDaemon         ActorType = "daemon"
	ActorTypeServiceAccount ActorType = "service_account"
)

type Actor struct {
	ID   string
	Name string
	Type ActorType
}

type AuditState struct {
	WorkspaceID string
	UserID      string
	Email       string
}

func WithWorkspaceID(ctx context.Context, workspaceID string) context.Context {
	return context.WithValue(ctx, WorkspaceKey, workspaceID)
}

func WorkspaceIDFromContext(ctx context.Context) string {
	workspaceID, _ := ctx.Value(WorkspaceKey).(string)
	return workspaceID
}

func WithAuditState(ctx context.Context, state *AuditState) context.Context {
	return context.WithValue(ctx, AuditStateKey, state)
}

func AuditStateFromContext(ctx context.Context) *AuditState {
	val, _ := ctx.Value(AuditStateKey).(*AuditState)
	return val
}

func SetAuditWorkspaceID(ctx context.Context, workspaceID string) {
	if a := AuditStateFromContext(ctx); a != nil {
		a.WorkspaceID = workspaceID
	}
}

func SetAuditEmail(ctx context.Context, email string) {
	if a := AuditStateFromContext(ctx); a != nil {
		a.Email = email
	}
}

func SetAuditUserID(ctx context.Context, userID string) {
	if a := AuditStateFromContext(ctx); a != nil {
		a.UserID = userID
	}
}

func WithActor(ctx context.Context, actor *Actor) context.Context {
	return context.WithValue(ctx, ActorKey, actor)
}

func ActorFromContext(ctx context.Context) *Actor {
	val, ok := ctx.Value(ActorKey).(*Actor)
	if !ok || val == nil {
		return &Actor{}
	}
	return val
}

func UserIDFromContext(ctx context.Context) string {
	actor := ActorFromContext(ctx)
	if actor.Type != ActorTypeUser {
		return ""
	}
	return actor.ID
}

func ServiceAccountIDFromContext(ctx context.Context) string {
	actor := ActorFromContext(ctx)
	if actor.Type != ActorTypeServiceAccount {
		return ""
	}
	return actor.ID
}

func DaemonIDFromContext(ctx context.Context) string {
	actor := ActorFromContext(ctx)
	if actor.Type != ActorTypeDaemon {
		return ""
	}
	return actor.ID
}
