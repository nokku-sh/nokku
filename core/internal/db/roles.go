package db

import (
	"strings"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// Roles are ordered, so "at least" is >= and zero passes nothing.

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
		return "Manage servers, access, daemons, teams, and service accounts"
	case nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN:
		return "Also manage members, invites, tokens, the certificate authority, and daemon defaults"
	case nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER:
		return "Also workspace settings, SSO, SCIM, billing, ownership transfer, and deleting the workspace"
	}
	return ""
}

// CanAssign stops at your own role, ownership only moves through a transfer.
func CanAssign(caller, target nokkuv1.WorkspaceRole) bool {
	return target > nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED &&
		target < nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER &&
		caller >= target
}
