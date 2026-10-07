// Package actor carries the request identity and its workspace through
// contexts. It has no dependencies so db can use it without import cycles.
package actor

import (
	"context"
)

type Kind string

const (
	KindUser           Kind = "user"
	KindCLI            Kind = "cli"
	KindDevice         Kind = "device"
	KindDaemon         Kind = "daemon"
	KindServiceAccount Kind = "service_account"
	KindSCIM           Kind = "scim"
)

type Principal struct {
	ID    string
	Kind  Kind
	Email string
	// Role is the user's or service account's role, empty for daemons and SCIM.
	Role string
}

// Workspace is the tenant a request runs in. The host names it before any
// authentication happens.
type Workspace struct {
	ID   string
	Slug string
	Name string
	// BaseURL is scheme and host with no path. Cookies, links, the passkey
	// RP ID and the DPoP htu all derive from it.
	BaseURL string
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
		case KindDaemon, KindServiceAccount, KindSCIM, KindDevice:
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

type workspaceKey struct{}

func WithWorkspace(ctx context.Context, ws Workspace) context.Context {
	return context.WithValue(ctx, workspaceKey{}, ws)
}

func WorkspaceFromContext(ctx context.Context) (Workspace, bool) {
	ws, ok := ctx.Value(workspaceKey{}).(Workspace)
	return ws, ok && ws.ID != ""
}

func WorkspaceIDFromContext(ctx context.Context) string {
	ws, _ := WorkspaceFromContext(ctx)
	return ws.ID
}
