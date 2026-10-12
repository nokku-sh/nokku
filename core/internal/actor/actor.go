// Package actor carries the request identity through contexts. It imports no sibling, so db can use it.
package actor

import (
	"context"
	"net/http"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

type Kind string

const (
	KindUser           Kind = "user"
	KindCLI            Kind = "cli"
	KindDaemon         Kind = "daemon"
	KindServiceAccount Kind = "service_account"
	KindSCIM           Kind = "scim"
)

type Principal struct {
	ID    string
	Kind  Kind
	Email string
	// Name is set for a service account, the audit log keeps it.
	Name string
	// Role is the user's or service account's role, unset for daemons and SCIM.
	Role nokkuv1.WorkspaceRole
}

// Workspace only holds what never changes, the name is read from the row.
type Workspace struct {
	ID   string
	Slug string
	// BaseURL is scheme and host. Cookies, links, the passkey RP ID and the DPoP htu derive from it.
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
		case KindDaemon, KindServiceAccount, KindSCIM:
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

// RequestMeta is what audit events and session rows take from the transport.
type RequestMeta struct {
	Header     http.Header
	RemoteAddr string
	// TLS is about the connection to this server. A proxy in front reports its own in X-Forwarded-Proto.
	TLS bool
}

type requestMetaKey struct{}

func ContextWithRequestMeta(ctx context.Context, meta RequestMeta) context.Context {
	return context.WithValue(ctx, requestMetaKey{}, meta)
}

func RequestMetaFromContext(ctx context.Context) (RequestMeta, bool) {
	m, ok := ctx.Value(requestMetaKey{}).(RequestMeta)
	return m, ok
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
