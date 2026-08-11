package db

import (
	"context"
	"fmt"
	"slices"
)

// Permission is a single action a role may perform on a resource.
//
// Codes are stored in roles.permissions and evaluated in Go by
// HasPermission, which the API's authorization interceptor consults before
// running any query. RLS policies enforce tenant isolation only and never
// inspect permission codes.
type Permission string

// Permission codes. Access levels are view < edit < delete and "edit" always
// implies "view". workspace.view is not enforced by RLS (reading a workspace
// is granted by membership) but it keeps the rule uniform.
const (
	PermWorkspaceView       Permission = "workspace.view"
	PermWorkspaceEdit       Permission = "workspace.edit"
	PermWorkspaceDelete     Permission = "workspace.delete"
	PermMembersView         Permission = "members.view"
	PermMembersEdit         Permission = "members.edit"
	PermSettingsView        Permission = "settings.view"
	PermSettingsEdit        Permission = "settings.edit"
	PermDomainsView         Permission = "domains.view"
	PermDomainsEdit         Permission = "domains.edit"
	PermSsoView             Permission = "sso.view"
	PermSsoEdit             Permission = "sso.edit"
	PermCasView             Permission = "cas.view"
	PermCasEdit             Permission = "cas.edit"
	PermTargetsView         Permission = "targets.view"
	PermTargetsEdit         Permission = "targets.edit"
	PermPrincipalsView      Permission = "principals.view"
	PermPrincipalsEdit      Permission = "principals.edit"
	PermDaemonsView         Permission = "daemons.view"
	PermDaemonsEdit         Permission = "daemons.edit"
	PermTeamsView           Permission = "teams.view"
	PermTeamsEdit           Permission = "teams.edit"
	PermServiceAccountsView Permission = "service_accounts.view"
	PermServiceAccountsEdit Permission = "service_accounts.edit"
)

// allPermissions enumerates the full vocabulary. Used by tests to validate
// that roles only reference known codes.
var allPermissions = []Permission{
	PermWorkspaceView,
	PermWorkspaceEdit,
	PermWorkspaceDelete,
	PermMembersView,
	PermMembersEdit,
	PermSettingsView,
	PermSettingsEdit,
	PermDomainsView,
	PermDomainsEdit,
	PermSsoView,
	PermSsoEdit,
	PermCasView,
	PermCasEdit,
	PermTargetsView,
	PermTargetsEdit,
	PermPrincipalsView,
	PermPrincipalsEdit,
	PermDaemonsView,
	PermDaemonsEdit,
	PermTeamsView,
	PermTeamsEdit,
	PermServiceAccountsView,
	PermServiceAccountsEdit,
}

// perm expands access levels for a resource into permission codes.
// "edit" expands to {"view", "edit"}; every other level is kept literally.
func perm(resource string, levels ...string) []Permission {
	out := make([]Permission, 0, len(levels)+1)
	for _, level := range levels {
		if level == "edit" {
			out = append(out, Permission(resource+".view"))
		}
		out = append(out, Permission(resource+"."+level))
	}
	return out
}

type builtinRole struct {
	name                        string
	description                 string
	permissions                 []Permission
	system                      bool // internal role, not exposed to users
	assignableToUsers           bool // grantable to members via role change
	assignableToServiceAccounts bool // grantable to service accounts
}

// builtinRoles is the source of truth for the authorization model.
// EnsureRoles converges the database onto it on startup.
var builtinRoles = []builtinRole{
	{
		// "owner" is granted via workspace creation and ownership transfer,
		// never through the role-change UI, so it is not assignable.
		name:        "owner",
		description: "Full access to all workspace resources and settings",
		permissions: slices.Concat(
			perm("workspace", "edit", "delete"),
			perm("members", "edit"),
			perm("settings", "edit"),
			perm("domains", "edit"),
			perm("sso", "edit"),
			perm("cas", "edit"),
			perm("targets", "edit"),
			perm("principals", "edit"),
			perm("daemons", "edit"),
			perm("teams", "edit"),
			perm("service_accounts", "edit"),
		),
	},
	{
		name:                        "editor",
		description:                 "Manage operational resources, certificate authorities, teams, and service accounts",
		assignableToUsers:           true,
		assignableToServiceAccounts: true,
		permissions: slices.Concat(
			perm("members", "view"),
			perm("settings", "view"),
			perm("domains", "view"),
			perm("sso", "view"),
			perm("cas", "edit"),
			perm("targets", "edit"),
			perm("principals", "edit"),
			perm("daemons", "edit"),
			perm("teams", "edit"),
			perm("service_accounts", "edit"),
		),
	},
	{
		name:                        "viewer",
		description:                 "View workspace resources",
		assignableToUsers:           true,
		assignableToServiceAccounts: true,
		permissions: slices.Concat(
			perm("members", "view"),
			perm("settings", "view"),
			perm("domains", "view"),
			perm("sso", "view"),
			perm("cas", "view"),
			perm("targets", "view"),
			perm("principals", "view"),
			perm("daemons", "view"),
			perm("teams", "view"),
			perm("service_accounts", "view"),
		),
	},
	{
		// "daemon" is a system role, not assignable to users or service
		// accounts. Daemon agents always operate with this fixed set.
		name:        "daemon",
		description: "Fixed permissions for daemon agents",
		system:      true,
		permissions: slices.Concat(
			perm("cas", "view"),
			perm("targets", "edit"),
			perm("principals", "edit"),
			perm("daemons", "edit"),
		),
	},
}

// RoleInfo describes a role for API consumers.
type RoleInfo struct {
	Name                        string
	Description                 string
	Permissions                 []Permission
	AssignableToUsers           bool
	AssignableToServiceAccounts bool
}

// UserFacingRoles returns the roles that can be held by workspace members and
// service accounts, excluding system roles such as "daemon".
func UserFacingRoles() []RoleInfo {
	out := make([]RoleInfo, 0, len(builtinRoles))
	for _, r := range builtinRoles {
		if r.system {
			continue
		}
		out = append(out, RoleInfo{
			Name:                        r.name,
			Description:                 r.description,
			Permissions:                 slices.Clone(r.permissions),
			AssignableToUsers:           r.assignableToUsers,
			AssignableToServiceAccounts: r.assignableToServiceAccounts,
		})
	}
	return out
}

// IsServiceAccountRole reports whether a role may be assigned to a service
// account.
func IsServiceAccountRole(roleName string) bool {
	for _, r := range builtinRoles {
		if r.name == roleName {
			return r.assignableToServiceAccounts
		}
	}
	return false
}

// HasPermission reports whether the named role grants the permission.
// Unknown roles have no permissions; this is the single point where
// permission codes are evaluated, and it replaces the SQL-side
// has_permission() that previously ran inside RLS policies.
func HasPermission(roleName string, p Permission) bool {
	for _, r := range builtinRoles {
		if r.name == roleName {
			return slices.Contains(r.permissions, p)
		}
	}
	return false
}

// setupRBACRoles converges the built-in roles onto the definitions above.
// Safe to run on every startup: adding, adjusting, or removing
// permissions here is applied automatically on the next boot.
func (c *Connection) setupRBACRoles(ctx context.Context) error {
	tx, err := c.AdminPool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := New(tx)
	for _, r := range builtinRoles {
		permissions := make([]string, len(r.permissions))
		for i, p := range r.permissions {
			permissions[i] = string(p)
		}

		if err := q.UpsertRole(ctx, &UpsertRoleParams{
			Name:        r.name,
			Description: r.description,
			Permissions: permissions,
		}); err != nil {
			return fmt.Errorf("ensuring role %q: %w", r.name, err)
		}
	}

	return tx.Commit(ctx)
}
