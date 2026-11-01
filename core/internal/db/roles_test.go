package db

import (
	"testing"

	"github.com/stretchr/testify/assert"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

func TestCanAssign(t *testing.T) {
	const (
		none   = nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED
		member = nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER
		editor = nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR
		admin  = nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN
		owner  = nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER
	)
	tests := []struct {
		caller, target nokkuv1.WorkspaceRole
		want           bool
	}{
		{admin, admin, true},
		{admin, member, true},
		{editor, admin, false},
		{admin, owner, false},
		{owner, owner, false},
		{owner, none, false},
		{owner, nokkuv1.WorkspaceRole(99), false},
		{none, member, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, CanAssign(tt.caller, tt.target), "CanAssign(%s, %s)", tt.caller, tt.target)
	}
}

func TestRoleLabel(t *testing.T) {
	assert.Equal(t, "admin", RoleLabel(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
}
