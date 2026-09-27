package iam

// Request identity re-exports: the principal and tenant context primitives
// live in internal/actor so the db layer can read them without importing iam.

import "github.com/nokku-sh/nokku/internal/actor"

// Kind is the actor kind a session belongs to.
type Kind = actor.Kind

const (
	KindUser           = actor.KindUser
	KindCLI            = actor.KindCLI
	KindWebDevice      = actor.KindWebDevice
	KindDaemon         = actor.KindDaemon
	KindServiceAccount = actor.KindServiceAccount
	KindSCIM           = actor.KindSCIM
)

// Principal is the authenticated actor of a request.
type Principal = actor.Principal

// TenantID is the resolved workspace of a request.
type TenantID = actor.TenantID

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
)
