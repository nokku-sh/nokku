package auth

import (
	"context"

	"github.com/mizuchilabs/kagi"
)

// Principal kinds that authenticate against nokku. These alias kagi.Kind so
// the auth facade and its callers share one type.
const (
	ActorTypeUser           kagi.Kind = "user"
	ActorTypeDevice         kagi.Kind = "device"
	ActorTypeDaemon         kagi.Kind = "daemon"
	ActorTypeServiceAccount kagi.Kind = "service_account"
)

// WorkspaceIDFromContext returns the workspace a request acts in: the tenant
// carried by a machine principal, or the tenant resolved from the request for
// global user principals.
func WorkspaceIDFromContext(ctx context.Context) string {
	if p, ok := kagi.PrincipalFromContext(ctx); ok && p.TenantID != "" {
		return string(p.TenantID)
	}
	t, _ := kagi.TenantFromContext(ctx)
	return string(t)
}

// UserIDFromContext returns the user subject id when the request acts as a
// human user.
func UserIDFromContext(ctx context.Context) string {
	p, ok := kagi.PrincipalFromContext(ctx)
	if !ok || p.Kind != ActorTypeUser {
		return ""
	}
	return p.SubjectID
}

// DaemonIDFromContext returns the daemon id when the request acts as a daemon.
func DaemonIDFromContext(ctx context.Context) string {
	p, ok := kagi.PrincipalFromContext(ctx)
	if !ok || p.Kind != ActorTypeDaemon {
		return ""
	}
	return p.SubjectID
}
