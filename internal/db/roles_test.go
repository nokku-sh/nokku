package db

import (
	"testing"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
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
		if got := CanAssign(tt.caller, tt.target); got != tt.want {
			t.Errorf("CanAssign(%s, %s) = %v, want %v", tt.caller, tt.target, got, tt.want)
		}
	}
}

func TestRoleLabel(t *testing.T) {
	if got := RoleLabel(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN); got != "admin" {
		t.Errorf("RoleLabel(admin) = %q", got)
	}
}
