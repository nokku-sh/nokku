// Package actor carries the request identity through contexts. It has no
// dependencies so db can use it without import cycles.
package actor

import (
	"context"
)

type Kind string

const (
	KindUser           Kind = "user"
	KindCLI            Kind = "cli"
	KindWebDevice      Kind = "web_device"
	KindDaemon         Kind = "daemon"
	KindServiceAccount Kind = "service_account"
	KindSCIM           Kind = "scim"
)

type Principal struct {
	ID    string
	Kind  Kind
	Email string
	// WorkspaceID is set for machine principals, empty for global actors.
	WorkspaceID string
}

type principalKey struct{}

func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// UserIDFromContext also covers CLI sessions, which act for a user.
func UserIDFromContext(ctx context.Context) string {
	if p, ok := PrincipalFromContext(ctx); ok {
		switch p.Kind {
		case KindUser, KindCLI:
			return p.ID
		case KindDaemon, KindServiceAccount, KindSCIM, KindWebDevice:
			return ""
		}
	}
	return ""
}

func DaemonIDFromContext(ctx context.Context) string {
	if p, ok := PrincipalFromContext(ctx); ok && p.Kind == KindDaemon {
		return p.ID
	}
	return ""
}

func SubjectFromContext(ctx context.Context) string {
	if p, ok := PrincipalFromContext(ctx); ok {
		return p.ID
	}
	return ""
}

type TenantID = string

type tenantKey struct{}

func AnnotateTenant(ctx context.Context, t TenantID) context.Context {
	return context.WithValue(ctx, tenantKey{}, t)
}

func tenantFromContext(ctx context.Context) (TenantID, bool) {
	t, ok := ctx.Value(tenantKey{}).(TenantID)
	return t, ok
}

func WorkspaceIDFromContext(ctx context.Context) string {
	t, _ := tenantFromContext(ctx)
	return t
}

type memberKey struct{}

type membership struct {
	workspaceID string
	role        string
}

// WithMember records a verified membership so later layers skip the lookup.
func WithMember(ctx context.Context, workspaceID, role string) context.Context {
	return context.WithValue(ctx, memberKey{}, membership{workspaceID, role})
}

func MemberOf(ctx context.Context) string {
	m, _ := ctx.Value(memberKey{}).(membership)
	return m.workspaceID
}

func MemberRole(ctx context.Context) string {
	m, _ := ctx.Value(memberKey{}).(membership)
	return m.role
}
