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

func WithAuditState(ctx context.Context, state *AuditState) context.Context {
	return context.WithValue(ctx, AuditStateKey, state)
}

func AuditStateFromContext(ctx context.Context) *AuditState {
	val, _ := ctx.Value(AuditStateKey).(*AuditState)
	return val
}

func WorkspaceIDFromContext(ctx context.Context) string {
	a := AuditStateFromContext(ctx)
	if a == nil {
		return ""
	}
	return a.WorkspaceID
}

func SetAuditWorkspaceID(ctx context.Context, workspaceID string) {
	if a := AuditStateFromContext(ctx); a != nil {
		a.WorkspaceID = workspaceID
	}
}

// SetAuditEmail records the account identifier attempted by the current
// request on the audit state. Used by auth handlers so failed login/register
// attempts still carry the email that was tried.
func SetAuditEmail(ctx context.Context, email string) {
	if a := AuditStateFromContext(ctx); a != nil {
		a.Email = email
	}
}

// SetAuditUserID records the actor that completed the current request on the
// audit state. Used by auth handlers to attribute successful logins when the
// actor was only known after authentication completed.
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

func ActorIDFromContext(ctx context.Context) string {
	return ActorFromContext(ctx).ID
}

func IsUser(ctx context.Context) bool {
	return ActorFromContext(ctx).Type == ActorTypeUser
}

func IsServiceAccount(ctx context.Context) bool {
	return ActorFromContext(ctx).Type == ActorTypeServiceAccount
}

func IsDaemon(ctx context.Context) bool {
	return ActorFromContext(ctx).Type == ActorTypeDaemon
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
