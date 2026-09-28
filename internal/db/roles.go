package db

import "slices"

// Role is a workspace role. Roles are ordered: each one includes everything
// the roles before it may do, so a check is a single comparison. The
// role_name columns hold these names, guarded by a CHECK constraint.
type Role string

const (
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
	RoleAdmin  Role = "admin"
	RoleOwner  Role = "owner"
)

// Roles lists every role from least to most privileged.
var Roles = []Role{RoleMember, RoleViewer, RoleEditor, RoleAdmin, RoleOwner}

// Description is the one-line summary the UI shows next to a role.
func (r Role) Description() string {
	switch r {
	case RoleMember:
		return "Use the access granted to them"
	case RoleViewer:
		return "Read everything in the workspace, including the audit log"
	case RoleEditor:
		return "Manage targets, access, daemons, certificate authorities, teams, and service accounts"
	case RoleAdmin:
		return "Also manage members, invites, SSO, domains, and workspace settings"
	case RoleOwner:
		return "Also billing, ownership transfer, and deleting the workspace"
	}
	return ""
}

// AtLeast reports whether r grants everything required grants. An unknown role
// satisfies nothing.
func (r Role) AtLeast(required Role) bool {
	rank := slices.Index(Roles, r)
	return rank >= 0 && rank >= slices.Index(Roles, required)
}

// CanAssign reports whether an actor holding r may give target to someone or
// act on someone who holds it. Nobody manages above their own role, and
// ownership only moves through a transfer.
func (r Role) CanAssign(target Role) bool {
	return target != RoleOwner && slices.Contains(Roles, target) && r.AtLeast(target)
}
