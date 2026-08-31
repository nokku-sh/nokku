package api

import (
	"testing"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
)

func TestProcedurePermissions(t *testing.T) {
	tests := []struct {
		procedure string
		want      db.Permission
	}{
		{nokkuv1connect.TargetServiceGetTargetProcedure, db.PermTargetsView},
		{nokkuv1connect.TargetServiceListTargetsProcedure, db.PermTargetsView},
		{nokkuv1connect.TargetServiceCreateTargetProcedure, db.PermTargetsEdit},
		{nokkuv1connect.TargetServiceDeleteTargetProcedure, db.PermTargetsEdit},

		{nokkuv1connect.TeamServiceGetTeamProcedure, db.PermTeamsView},
		{nokkuv1connect.TeamServiceAddTeamMemberProcedure, db.PermTeamsEdit},

		{nokkuv1connect.CertificateServiceGetCertificateAuthorityProcedure, db.PermCasView},
		{nokkuv1connect.CertificateServiceDeleteCertificateAuthorityProcedure, db.PermCasEdit},

		{nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure, db.PermWorkspaceEdit},
		{nokkuv1connect.WorkspaceServiceDeleteWorkspaceProcedure, db.PermWorkspaceDelete},
		{nokkuv1connect.WorkspaceServiceListWorkspaceMembersProcedure, db.PermMembersView},
		{nokkuv1connect.WorkspaceServiceUpdateWorkspaceMemberProcedure, db.PermMembersEdit},

		{nokkuv1connect.PrincipalServiceListPrincipalsProcedure, db.PermPrincipalsView},
		{nokkuv1connect.PrincipalServiceRevokeAllAccessProcedure, db.PermPrincipalsEdit},

		{
			nokkuv1connect.ServiceAccountServiceGetServiceAccountProcedure,
			db.PermServiceAccountsView,
		},
		{
			nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure,
			db.PermServiceAccountsEdit,
		},

		{nokkuv1connect.DaemonServiceGetDaemonProcedure, db.PermDaemonsView},
		{nokkuv1connect.DaemonServiceDeleteDaemonProcedure, db.PermDaemonsEdit},
		{nokkuv1connect.DaemonServiceRefreshEnrollTokenProcedure, db.PermSettingsEdit},

		{nokkuv1connect.SSOServiceGetOIDCProviderProcedure, db.PermSsoView},
		{nokkuv1connect.SSOServiceUpdateSAMLProviderProcedure, db.PermSsoEdit},

		{nokkuv1connect.WorkspaceDomainServiceGetWorkspaceDomainProcedure, db.PermDomainsView},
		{nokkuv1connect.WorkspaceDomainServiceVerifyWorkspaceDomainProcedure, db.PermDomainsEdit},

		{nokkuv1connect.BillingServiceGetBillingProcedure, db.PermSettingsView},
		{nokkuv1connect.InvitationServiceRefreshInviteTokenProcedure, db.PermSettingsEdit},
	}

	for _, test := range tests {
		t.Run(test.procedure, func(t *testing.T) {
			if got := ProcedurePermissions[test.procedure]; got != test.want {
				t.Fatalf("permission = %q, want %q", got, test.want)
			}
		})
	}
}

// Procedures with user-scoped, token-scoped, owner-only, public, or streaming
// handling must NOT be registered, or the interceptor would wrongly enforce a
// workspace permission on them.
func TestProcedurePermissionsExcludesSpecialProcedures(t *testing.T) {
	special := []string{
		nokkuv1connect.WorkspaceServiceGetWorkspaceProcedure,
		nokkuv1connect.WorkspaceServiceListWorkspacesProcedure,
		nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure,
		nokkuv1connect.WorkspaceServiceRemoveWorkspaceMemberProcedure,
		nokkuv1connect.WorkspaceServiceUpdateWorkspaceOwnerProcedure,
		nokkuv1connect.WorkspaceServiceSubscribeWorkspaceEventsProcedure,
		nokkuv1connect.BillingServiceCreateCheckoutProcedure,
		nokkuv1connect.BillingServiceCancelSubscriptionProcedure,
		nokkuv1connect.DaemonServiceEnrollDaemonProcedure,
		nokkuv1connect.DaemonServiceSyncDaemonProcedure,
		nokkuv1connect.CertificateServiceSignSSHCertificateProcedure,
		nokkuv1connect.CertificateServiceSignX509CertificateProcedure,
		nokkuv1connect.InvitationServiceGetInvitationProcedure,
		nokkuv1connect.InvitationServiceAcceptInvitationProcedure,
		nokkuv1connect.UtilServiceListAuditLogsProcedure,
		nokkuv1connect.UtilServiceExportAuditLogsProcedure,
		nokkuv1connect.UserServiceWhoamiProcedure,
	}

	for _, procedure := range special {
		if _, ok := ProcedurePermissions[procedure]; ok {
			t.Fatalf("%s unexpectedly has a procedure permission rule", procedure)
		}
	}
}

func TestProcedurePermissionsDoesNotAuthorizeUnknownProcedures(t *testing.T) {
	if _, ok := ProcedurePermissions["/nokku.v1.UnknownService/Unknown"]; ok {
		t.Fatal("unknown procedure unexpectedly has an authorization rule")
	}
}
