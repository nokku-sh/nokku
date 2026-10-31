// Package actor carries the request identity through contexts. Its one sibling import, realip, imports none, so
// db can use it.
package actor

import (
	"context"
	"net/http"
	"strings"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/realip"
)

// maxUserAgent keeps a hostile header from bloating the rows that store it.
const maxUserAgent = 512

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
}

// ClientIP is the client's address as stored, see [realip.Client].
func (m RequestMeta) ClientIP() string {
	return strings.ToValidUTF8(realip.Client(m.Header, m.RemoteAddr), "")
}

// UserAgent is the header as stored, valid UTF-8 and cut to 512 bytes.
func (m RequestMeta) UserAgent() string {
	ua := strings.ToValidUTF8(m.Header.Get("User-Agent"), "")
	if len(ua) <= maxUserAgent {
		return ua
	}
	return strings.ToValidUTF8(ua[:maxUserAgent], "")
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
