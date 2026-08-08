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

// WithWorkspaceID records the workspace selected for the current request.
// The value is consumed by database scoping and audit logging.
func WithWorkspaceID(ctx context.Context, workspaceID string) context.Context {
	return context.WithValue(ctx, WorkspaceKey, workspaceID)
}

func WorkspaceIDFromContext(ctx context.Context) (string, bool) {
	workspaceID, ok := ctx.Value(WorkspaceKey).(string)
	return workspaceID, ok && workspaceID != ""
}

func WithAuditState(ctx context.Context, state *AuditState) context.Context {
	return context.WithValue(ctx, AuditStateKey, state)
}

func AuditStateFromContext(ctx context.Context) *AuditState {
	val, _ := ctx.Value(AuditStateKey).(*AuditState)
	return val
}

// SetAuditWorkspaceID is reserved for streaming handlers whose request
// message is received inside the business method and therefore cannot be
// inspected by the unary request interceptor.
func SetAuditWorkspaceID(ctx context.Context, workspaceID string) {
	if a := AuditStateFromContext(ctx); a != nil {
		a.WorkspaceID = workspaceID
	}
}

// SetAuditEmail records the email the current request attempted, so failed
// login/register attempts still carry it on the audit state.
func SetAuditEmail(ctx context.Context, email string) {
	if a := AuditStateFromContext(ctx); a != nil {
		a.Email = email
	}
}

// SetAuditUserID records the actor that completed the current request, for
// logins where the actor is only known after authentication completes.
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
