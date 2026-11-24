package db

import (
	"strings"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// Roles are ordered, so "at least" is >= and zero passes nothing.

func RoleLabel(r nokkuv1.WorkspaceRole) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "WORKSPACE_ROLE_"))
}

// CanAssign stops at your own role, ownership only moves through a transfer.
func CanAssign(caller, target nokkuv1.WorkspaceRole) bool {
	return target > nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED &&
		target < nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER &&
		caller >= target
}
