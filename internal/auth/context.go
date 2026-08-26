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

// WorkspaceIDFromContext returns the workspace a request acts in. kagi
// guarantees the effective tenant is always on the request identity: the
// credential tenant for machine principals, otherwise the tenant resolved
// from the request.
func WorkspaceIDFromContext(ctx context.Context) string {
	t, _ := kagi.TenantFromContext(ctx)
	return string(t)
}

// UserIDFromContext returns the user subject id when the request acts as a
// human user. Device sessions also resolve: the CLI authenticates on the
// user's behalf through the device flow, so its subject is the user id.
func UserIDFromContext(ctx context.Context) string {
	p, ok := kagi.PrincipalFromContext(ctx)
	if !ok {
		return ""
	}
	switch p.Kind {
	case ActorTypeUser, ActorTypeDevice:
		return p.SubjectID
	default:
		return ""
	}
}

// DaemonIDFromContext returns the daemon id when the request acts as a daemon.
func DaemonIDFromContext(ctx context.Context) string {
	p, ok := kagi.PrincipalFromContext(ctx)
	if !ok || p.Kind != ActorTypeDaemon {
		return ""
	}
	return p.SubjectID
}
