package db

import "slices"

// Role values are ordered, each includes everything the ones before it may do.
type Role string

const (
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
	RoleAdmin  Role = "admin"
	RoleOwner  Role = "owner"
)

var Roles = []Role{RoleMember, RoleViewer, RoleEditor, RoleAdmin, RoleOwner}

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

// AtLeast is false for unknown roles.
func (r Role) AtLeast(required Role) bool {
	rank := slices.Index(Roles, r)
	return rank >= 0 && rank >= slices.Index(Roles, required)
}

// CanAssign never allows managing above your own role, and ownership only
// moves through a transfer.
func (r Role) CanAssign(target Role) bool {
	return target != RoleOwner && slices.Contains(Roles, target) && r.AtLeast(target)
}
