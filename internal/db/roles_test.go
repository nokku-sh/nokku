package db

import (
	"strings"
	"testing"
)

func TestBuiltinRolesUseKnownPermissions(t *testing.T) {
	known := make(map[Permission]bool, len(allPermissions))
	for _, p := range allPermissions {
		known[p] = true
	}

	for _, role := range builtinRoles {
		for _, p := range role.permissions {
			if !known[p] {
				t.Errorf("role %q references unknown permission %q", role.name, p)
			}
		}
	}
}

func TestEveryPermissionIsAssigned(t *testing.T) {
	used := make(map[Permission]bool)
	for _, role := range builtinRoles {
		for _, p := range role.permissions {
			used[p] = true
		}
	}

	for _, p := range allPermissions {
		if !used[p] {
			t.Errorf("permission %q is not assigned to any built-in role", p)
		}
	}
}

func TestNoDuplicatePermissions(t *testing.T) {
	for _, role := range builtinRoles {
		seen := make(map[Permission]bool, len(role.permissions))
		for _, p := range role.permissions {
			if seen[p] {
				t.Errorf("role %q has duplicate permission %q", role.name, p)
			}
			seen[p] = true
		}
	}
}

func TestEditImpliesView(t *testing.T) {
	for _, role := range builtinRoles {
		perms := permSet(role.permissions)
		for _, p := range role.permissions {
			if !strings.HasSuffix(string(p), ".edit") {
				continue
			}
			view := Permission(strings.TrimSuffix(string(p), ".edit") + ".view")
			if !perms[view] {
				t.Errorf("role %q has %q but not %q", role.name, p, view)
			}
		}
	}
}

func TestRoleHierarchy(t *testing.T) {
	owner := permSet(roleByName(t, "owner"))
	editor := permSet(roleByName(t, "editor"))
	viewer := permSet(roleByName(t, "viewer"))

	if !superset(owner, editor) {
		t.Error("owner should have every editor permission")
	}
	if !superset(owner, viewer) {
		t.Error("owner should have every viewer permission")
	}
	if !superset(editor, viewer) {
		t.Error("editor should have every viewer permission")
	}
}

func TestServiceAccountRoles(t *testing.T) {
	for _, role := range []string{"viewer", "editor"} {
		if !IsServiceAccountRole(role) {
			t.Errorf("expected %q to be assignable to a service account", role)
		}
	}
	for _, role := range []string{"owner", "daemon", "", "custom"} {
		if IsServiceAccountRole(role) {
			t.Errorf("did not expect %q to be assignable to a service account", role)
		}
	}
}

func TestUserFacingRoles(t *testing.T) {
	roles := UserFacingRoles()
	if len(roles) != 3 {
		t.Fatalf("expected 3 user-facing roles, got %d", len(roles))
	}

	byName := make(map[string]RoleInfo, len(roles))
	for _, r := range roles {
		byName[r.Name] = r
	}

	owner, ok := byName["owner"]
	if !ok {
		t.Fatal("expected owner role")
	}
	if owner.AssignableToUsers || owner.AssignableToServiceAccounts {
		t.Error("owner should not be assignable via role change")
	}

	for _, role := range []string{"editor", "viewer"} {
		r, ok := byName[role]
		if !ok {
			t.Fatalf("expected %q role", role)
		}
		if !r.AssignableToUsers || !r.AssignableToServiceAccounts {
			t.Errorf("%q should be assignable to users and service accounts", role)
		}
	}
}

func roleByName(t *testing.T, name string) []Permission {
	t.Helper()
	for _, r := range builtinRoles {
		if r.name == name {
			return r.permissions
		}
	}
	t.Fatalf("role %q not found", name)
	return nil
}

func permSet(perms []Permission) map[Permission]bool {
	out := make(map[Permission]bool, len(perms))
	for _, p := range perms {
		out[p] = true
	}
	return out
}

func superset(a, b map[Permission]bool) bool {
	for p := range b {
		if !a[p] {
			return false
		}
	}
	return true
}
