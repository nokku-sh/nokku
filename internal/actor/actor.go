// Package actor carries the request identity through contexts. It is
// dependency-free so the db layer (which reads the tenant for RLS) can share
// the vocabulary with iam and the api without import cycles.
package actor

import (
	"context"
)

// Kind is the actor kind a session belongs to.
type Kind string

const (
	KindUser           Kind = "user"
	KindCLI            Kind = "cli"
	KindWebDevice      Kind = "web_device"
	KindDaemon         Kind = "daemon"
	KindServiceAccount Kind = "service_account"
	// KindSCIM is a SCIM connector token, pinned to its workspace.
	KindSCIM Kind = "scim"
)

// Principal is the authenticated actor of a request. It mirrors what the
// transport layer resolved: a user session, a CLI device, or a daemon.
type Principal struct {
	ID string
	// Kind is the actor kind: user, cli, web_device, or daemon.
	Kind Kind
	// Email is the user's email for user sessions, empty otherwise.
	Email string
	// WorkspaceID is the tenant pin from the session (daemons); empty when
	// the actor is global.
	WorkspaceID string
}

// principalKey is unexported so only this package stores principals.
type principalKey struct{}

// ContextWithPrincipal returns a context carrying p.
func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext returns the request principal and whether one is set.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// UserIDFromContext returns the principal's user id: the user for user
// sessions, and the acting user for CLI device sessions (the device flow
// authenticates on the user's behalf). Empty otherwise.
func UserIDFromContext(ctx context.Context) string {
	if p, ok := PrincipalFromContext(ctx); ok {
		switch p.Kind {
		case KindUser, KindCLI, KindWebDevice:
			return p.ID
		case KindDaemon, KindServiceAccount, KindSCIM:
			return ""
		}
	}
	return ""
}

// DaemonIDFromContext returns the daemon id when the request acts as a
// daemon.
func DaemonIDFromContext(ctx context.Context) string {
	if p, ok := PrincipalFromContext(ctx); ok && p.Kind == KindDaemon {
		return p.ID
	}
	return ""
}

// SubjectFromContext returns the principal's subject ID: the user, CLI
// device, or daemon ID the session was issued to.
func SubjectFromContext(ctx context.Context) string {
	if p, ok := PrincipalFromContext(ctx); ok {
		return p.ID
	}
	return ""
}

// TenantID is the workspace a request acts in. The transport resolves it
// (request workspace field, header, or the credential's pin) and annotates
// the request context; the DB layer reads it for row-level security.
type TenantID = string

// tenantKey is unexported so only this package stores tenants.
type tenantKey struct{}

// AnnotateTenant returns a context carrying the resolved workspace.
func AnnotateTenant(ctx context.Context, t TenantID) context.Context {
	return context.WithValue(ctx, tenantKey{}, t)
}

// TenantFromContext returns the resolved workspace and whether one is set.
func TenantFromContext(ctx context.Context) (TenantID, bool) {
	t, ok := ctx.Value(tenantKey{}).(TenantID)
	return t, ok
}

// WorkspaceIDFromContext returns the workspace a request acts in: the
// credential's pinned workspace for machine principals, otherwise the
// workspace the transport resolved from the request.
func WorkspaceIDFromContext(ctx context.Context) string {
	t, _ := TenantFromContext(ctx)
	return t
}

type memberKey struct{}

type membership struct {
	workspaceID string
	role        string
}

// WithMember records that authorization verified the actor's membership in
// workspaceID with role, so the DB layer and handlers skip a second lookup.
func WithMember(ctx context.Context, workspaceID, role string) context.Context {
	return context.WithValue(ctx, memberKey{}, membership{workspaceID, role})
}

// MemberOf returns the workspace whose membership authorization verified.
func MemberOf(ctx context.Context) string {
	m, _ := ctx.Value(memberKey{}).(membership)
	return m.workspaceID
}

// MemberRole returns the role authorization verified, empty when none was.
func MemberRole(ctx context.Context) string {
	m, _ := ctx.Value(memberKey{}).(membership)
	return m.role
}
