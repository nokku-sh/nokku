package db

import (
	"strings"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// A role is the WorkspaceRole of the protos. The values are ordered, so "at least" is >= and zero passes nothing.

// RoleLabel is the role as people read it, like "admin".
func RoleLabel(r nokkuv1.WorkspaceRole) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "WORKSPACE_ROLE_"))
}

func RoleDescription(r nokkuv1.WorkspaceRole) string {
	//nolint:exhaustive // no role has no description
	switch r {
	case nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER:
		return "Use the access granted to them"
	case nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER:
		return "Read everything in the workspace, including the audit log"
	case nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR:
		return "Manage targets, access, daemons, certificate authorities, teams, and service accounts"
	case nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN:
		return "Also manage members, invites, and tokens"
	case nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER:
		return "Also workspace settings, SSO, domains, SCIM, billing, ownership transfer, and deleting the workspace"
	}
	return ""
}

// CanAssign never allows managing above your own role, and ownership only moves through a transfer.
func CanAssign(caller, target nokkuv1.WorkspaceRole) bool {
	return target > nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED &&
		target < nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER &&
		caller >= target
}
