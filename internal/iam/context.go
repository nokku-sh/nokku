package iam

// Re-exports from internal/actor, which exists so db can read them without importing iam.

import "github.com/nokku-sh/nokku/internal/actor"

type Kind = actor.Kind

const (
	KindUser           = actor.KindUser
	KindCLI            = actor.KindCLI
	KindWebDevice      = actor.KindWebDevice
	KindDaemon         = actor.KindDaemon
	KindServiceAccount = actor.KindServiceAccount
	KindSCIM           = actor.KindSCIM
)

type (
	Principal = actor.Principal
	TenantID  = actor.TenantID
)

var (
	ContextWithPrincipal   = actor.ContextWithPrincipal
	PrincipalFromContext   = actor.PrincipalFromContext
	UserIDFromContext      = actor.UserIDFromContext
	DaemonIDFromContext    = actor.DaemonIDFromContext
	SubjectFromContext     = actor.SubjectFromContext
	AnnotateTenant         = actor.AnnotateTenant
	TenantFromContext      = actor.TenantFromContext
	WorkspaceIDFromContext = actor.WorkspaceIDFromContext
	WithMember             = actor.WithMember
	MemberRole             = actor.MemberRole
)
