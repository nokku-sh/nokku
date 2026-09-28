package db

import "testing"

func TestRoleAtLeast(t *testing.T) {
	tests := []struct {
		role, required Role
		want           bool
	}{
		{RoleOwner, RoleMember, true},
		{RoleEditor, RoleEditor, true},
		{RoleViewer, RoleEditor, false},
		{Role("root"), RoleMember, false},
	}
	for _, tt := range tests {
		if got := tt.role.AtLeast(tt.required); got != tt.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", tt.role, tt.required, got, tt.want)
		}
	}
}

func TestRoleCanAssign(t *testing.T) {
	tests := []struct {
		actor, target Role
		want          bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleMember, true},
		{RoleEditor, RoleAdmin, false},
		{RoleAdmin, RoleOwner, false},
		{RoleOwner, RoleOwner, false},
		{RoleOwner, Role("root"), false},
	}
	for _, tt := range tests {
		if got := tt.actor.CanAssign(tt.target); got != tt.want {
			t.Errorf("%s.CanAssign(%s) = %v, want %v", tt.actor, tt.target, got, tt.want)
		}
	}
}
