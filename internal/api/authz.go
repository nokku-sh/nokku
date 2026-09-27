package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/iam"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
)

// Every procedure is classified exactly once, here or in publicEndpoints.
// Anything unclassified is denied, so a new RPC fails closed until someone
// decides who may call it.

// ProcedurePermissions maps every workspace-scoped procedure to the single
// permission it requires. This is the only place permission codes are
// resolved from a procedure. Handlers run their data access with plain
// WithWorkspace.
var ProcedurePermissions = map[string]db.Permission{
	// Billing
	nokkuv1connect.BillingServiceGetBillingProcedure: db.PermSettingsView,

	// Certificate authorities
	nokkuv1connect.CertificateServiceGetCertificateAuthorityProcedure:      db.PermCasView,
	nokkuv1connect.CertificateServiceListCertificateAuthoritiesProcedure:   db.PermCasView,
	nokkuv1connect.CertificateServiceCreateCertificateAuthorityProcedure:   db.PermCasEdit,
	nokkuv1connect.CertificateServiceUpdateCertificateAuthorityProcedure:   db.PermCasEdit,
	nokkuv1connect.CertificateServiceDeleteCertificateAuthorityProcedure:   db.PermCasEdit,
	nokkuv1connect.CertificateServiceRolloverCertificateAuthorityProcedure: db.PermCasEdit,

	// Daemons
	nokkuv1connect.DaemonServiceGetDaemonProcedure:     db.PermDaemonsView,
	nokkuv1connect.DaemonServiceListDaemonsProcedure:   db.PermDaemonsView,
	nokkuv1connect.DaemonServiceListSessionsProcedure:  db.PermDaemonsView,
	nokkuv1connect.DaemonServiceCreateSessionProcedure: db.PermDaemonsView,
	nokkuv1connect.DaemonServiceUpdateDaemonProcedure:  db.PermDaemonsEdit,
	nokkuv1connect.DaemonServiceDeleteDaemonProcedure:  db.PermDaemonsEdit,

	// Join tokens (enroll and invite)
	nokkuv1connect.TokenServiceCreateTokenProcedure: db.PermSettingsEdit,
	nokkuv1connect.TokenServiceListTokensProcedure:  db.PermSettingsView,
	nokkuv1connect.TokenServiceDeleteTokenProcedure: db.PermSettingsEdit,

	// Principals
	nokkuv1connect.PrincipalServiceListPrincipalsProcedure:              db.PermPrincipalsView,
	nokkuv1connect.PrincipalServiceAddSubjectsToPrincipalProcedure:      db.PermPrincipalsEdit,
	nokkuv1connect.PrincipalServiceRemoveSubjectsFromPrincipalProcedure: db.PermPrincipalsEdit,
	nokkuv1connect.PrincipalServiceRevokeAllAccessProcedure:             db.PermPrincipalsEdit,
	nokkuv1connect.PrincipalServiceAddPrincipalProcedure:                db.PermPrincipalsEdit,
	nokkuv1connect.PrincipalServiceRemovePrincipalProcedure:             db.PermPrincipalsEdit,

	// Service accounts
	nokkuv1connect.ServiceAccountServiceGetServiceAccountProcedure:    db.PermServiceAccountsView,
	nokkuv1connect.ServiceAccountServiceListServiceAccountsProcedure:  db.PermServiceAccountsView,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure: db.PermServiceAccountsEdit,
	nokkuv1connect.ServiceAccountServiceUpdateServiceAccountProcedure: db.PermServiceAccountsEdit,
	nokkuv1connect.ServiceAccountServiceDeleteServiceAccountProcedure: db.PermServiceAccountsEdit,

	// SSO
	nokkuv1connect.SSOServiceGetSSOProviderProcedure:    db.PermSsoView,
	nokkuv1connect.SSOServiceUpdateSSOProviderProcedure: db.PermSsoEdit,

	// SCIM connector tokens (the endpoint itself is token-scoped)
	nokkuv1connect.SCIMServiceCreateSCIMTokenProcedure: db.PermSettingsEdit,
	nokkuv1connect.SCIMServiceListSCIMTokensProcedure:  db.PermSettingsView,
	nokkuv1connect.SCIMServiceDeleteSCIMTokenProcedure: db.PermSettingsEdit,

	// Targets
	nokkuv1connect.TargetServiceGetTargetProcedure:           db.PermTargetsView,
	nokkuv1connect.TargetServiceListTargetsProcedure:         db.PermTargetsView,
	nokkuv1connect.TargetServiceGetSubjectAccessProcedure:    db.PermTargetsView,
	nokkuv1connect.TargetServiceGetTargetFiltersProcedure:    db.PermTargetsView,
	nokkuv1connect.TargetServiceCreateTargetProcedure:        db.PermTargetsEdit,
	nokkuv1connect.TargetServiceUpdateTargetProcedure:        db.PermTargetsEdit,
	nokkuv1connect.TargetServiceDeleteTargetProcedure:        db.PermTargetsEdit,
	nokkuv1connect.TargetServiceGetTargetPrincipalsProcedure: db.PermTargetsView,
	nokkuv1connect.TargetServiceSyncTargetUsersProcedure:     db.PermTargetsEdit,

	// Teams
	nokkuv1connect.TeamServiceGetTeamProcedure:          db.PermTeamsView,
	nokkuv1connect.TeamServiceListTeamsProcedure:        db.PermTeamsView,
	nokkuv1connect.TeamServiceCreateTeamProcedure:       db.PermTeamsEdit,
	nokkuv1connect.TeamServiceUpdateTeamProcedure:       db.PermTeamsEdit,
	nokkuv1connect.TeamServiceDeleteTeamProcedure:       db.PermTeamsEdit,
	nokkuv1connect.TeamServiceAddTeamMemberProcedure:    db.PermTeamsEdit,
	nokkuv1connect.TeamServiceRemoveTeamMemberProcedure: db.PermTeamsEdit,
	nokkuv1connect.TeamServiceListTeamMembersProcedure:  db.PermTeamsView,

	// Teams of one user are member-directory reads, not team-structure edits
	nokkuv1connect.TeamServiceListTeamsForUserProcedure: db.PermMembersView,

	// Workspaces
	nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure:       db.PermWorkspaceEdit,
	nokkuv1connect.WorkspaceServiceDeleteWorkspaceProcedure:       db.PermWorkspaceDelete,
	nokkuv1connect.WorkspaceServiceGetWorkspaceMemberProcedure:    db.PermMembersView,
	nokkuv1connect.WorkspaceServiceListWorkspaceMembersProcedure:  db.PermMembersView,
	nokkuv1connect.WorkspaceServiceUpdateWorkspaceMemberProcedure: db.PermMembersEdit,
	nokkuv1connect.WorkspaceServiceRemoveWorkspaceMemberProcedure: db.PermMembersEdit,

	// Workspace domains
	nokkuv1connect.WorkspaceDomainServiceGetWorkspaceDomainProcedure:             db.PermDomainsView,
	nokkuv1connect.WorkspaceDomainServiceListWorkspaceDomainsProcedure:           db.PermDomainsView,
	nokkuv1connect.WorkspaceDomainServiceCreateWorkspaceDomainProcedure:          db.PermDomainsEdit,
	nokkuv1connect.WorkspaceDomainServiceDeleteWorkspaceDomainProcedure:          db.PermDomainsEdit,
	nokkuv1connect.WorkspaceDomainServiceVerifyWorkspaceDomainProcedure:          db.PermDomainsEdit,
	nokkuv1connect.WorkspaceDomainServiceRegenerateWorkspaceDomainTokenProcedure: db.PermDomainsEdit,

	// Recordings
	nokkuv1connect.RecordingServiceListRecordingsProcedure:  db.PermDaemonsView,
	nokkuv1connect.RecordingServiceGetRecordingProcedure:    db.PermDaemonsView,
	nokkuv1connect.RecordingServiceDeleteRecordingProcedure: db.PermDaemonsEdit,

	nokkuv1connect.UtilServiceListAuditLogsProcedure:   db.PermAuditView,
	nokkuv1connect.UtilServiceExportAuditLogsProcedure: db.PermAuditView,

	nokkuv1connect.DaemonServiceCloseSessionProcedure: db.PermDaemonsEdit,
}

// selfScopedProcedures are open to any authenticated user or service
// account. Each one is scoped to the caller (their account, their
// workspaces, their certs) or checks owner rights in the handler.
var selfScopedProcedures = map[string]struct{}{
	nokkuv1connect.AccountServiceChangePasswordProcedure:             {},
	nokkuv1connect.AccountServiceDeleteAccountProcedure:              {},
	nokkuv1connect.AccountServiceGetAccountProcedure:                 {},
	nokkuv1connect.AccountServiceListAccountSessionsProcedure:        {},
	nokkuv1connect.AccountServiceListBackupCodesProcedure:            {},
	nokkuv1connect.AccountServiceListCredentialsProcedure:            {},
	nokkuv1connect.AccountServiceRemoveBackupCodesProcedure:          {},
	nokkuv1connect.AccountServiceRemoveCredentialProcedure:           {},
	nokkuv1connect.AccountServiceRemoveIdentityProcedure:             {},
	nokkuv1connect.AccountServiceRemovePasswordProcedure:             {},
	nokkuv1connect.AccountServiceRemoveSessionProcedure:              {},
	nokkuv1connect.AccountServiceRenameCredentialProcedure:           {},
	nokkuv1connect.AccountServiceRotateBackupCodesProcedure:          {},
	nokkuv1connect.AccountServiceUpdateAccountProcedure:              {},
	nokkuv1connect.BillingServiceCancelSubscriptionProcedure:         {},
	nokkuv1connect.BillingServiceCreateCheckoutProcedure:             {},
	nokkuv1connect.BillingServiceCreatePortalProcedure:               {},
	nokkuv1connect.BillingServiceGetLicenseProcedure:                 {},
	nokkuv1connect.CertificateServiceSignSSHCertificateProcedure:     {},
	nokkuv1connect.CertificateServiceSignX509CertificateProcedure:    {},
	nokkuv1connect.DaemonServiceRelayProcedure:                       {},
	nokkuv1connect.InvitationServiceAcceptInvitationProcedure:        {},
	nokkuv1connect.InvitationServiceGetInvitationProcedure:           {},
	nokkuv1connect.TargetServiceGetMyAccessProcedure:                 {},
	nokkuv1connect.UtilServiceListRolesProcedure:                     {},
	nokkuv1connect.UtilServiceWhoamiProcedure:                        {},
	nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure:          {},
	nokkuv1connect.WorkspaceServiceGetWorkspaceProcedure:             {},
	nokkuv1connect.WorkspaceServiceListWorkspacesProcedure:           {},
	nokkuv1connect.WorkspaceServiceSubscribeWorkspaceEventsProcedure: {},
	nokkuv1connect.WorkspaceServiceUpdateWorkspaceOwnerProcedure:     {},
}

// daemonOnlyProcedures serve the daemon identity and nobody else.
var daemonOnlyProcedures = map[string]struct{}{
	nokkuv1connect.DaemonServiceSyncDaemonProcedure:         {},
	nokkuv1connect.DaemonControlServiceConnectProcedure:     {},
	nokkuv1connect.DaemonSessionServiceDaemonRelayProcedure: {},
	nokkuv1connect.RecordingServiceUploadRecordingProcedure: {},
}

// daemonSharedProcedures are the only other procedures a daemon may call.
// Their handlers narrow a daemon to its own host cert and its own record.
var daemonSharedProcedures = map[string]struct{}{
	nokkuv1connect.CertificateServiceSignSSHCertificateProcedure: {},
	nokkuv1connect.DaemonServiceDeleteDaemonProcedure:            {},
}

type AuthorizationInterceptor struct {
	cfg *config.Config
}

func NewAuthZInterceptor(
	cfg *config.Config,
) *AuthorizationInterceptor {
	return &AuthorizationInterceptor{cfg: cfg}
}

func (a *AuthorizationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, err := a.authorize(ctx, req.Spec().Procedure)
		if err != nil {
			return nil, DBError(err)
		}
		return next(ctx, req)
	}
}

func (a *AuthorizationInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

func (a *AuthorizationInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := a.authorize(ctx, conn.Spec().Procedure)
		if err != nil {
			return DBError(err)
		}
		return next(ctx, conn)
	}
}

// authorize decides whether the request actor may call procedure at all. A
// workspace permission check also marks the membership as verified on the
// returned context, so WithWorkspace skips its own lookup.
func (a *AuthorizationInterceptor) authorize(
	ctx context.Context,
	procedure string,
) (context.Context, error) {
	actor, _ := iam.PrincipalFromContext(ctx)
	_, daemonOnly := daemonOnlyProcedures[procedure]
	if actor.Kind == iam.KindDaemon {
		if _, shared := daemonSharedProcedures[procedure]; daemonOnly || shared {
			return ctx, nil
		}
		return ctx, db.ErrPermissionDenied
	}
	if daemonOnly {
		return ctx, db.ErrPermissionDenied
	}
	if perm, ok := ProcedurePermissions[procedure]; ok {
		if err := actorHasPermission(ctx, a.cfg.Conn, perm); err != nil {
			return ctx, err
		}
		return iam.WithMember(ctx, iam.WorkspaceIDFromContext(ctx)), nil
	}
	if _, ok := selfScopedProcedures[procedure]; ok {
		return ctx, nil
	}
	if isPublicEndpoint(procedure) {
		return ctx, nil
	}
	return ctx, db.ErrPermissionDenied
}

// actorHasPermission resolves the request actor's role and checks it against
// the permission.
func actorHasPermission(
	ctx context.Context,
	conn *db.Connection,
	perm db.Permission,
) error {
	actor, _ := iam.PrincipalFromContext(ctx)
	if actor.ID == "" {
		return db.ErrNoActor
	}
	workspaceID := iam.WorkspaceIDFromContext(ctx)
	if workspaceID == "" {
		return db.ErrWorkspaceNotPinned
	}
	role, err := conn.Sys().GetActorRole(ctx, &db.GetActorRoleParams{
		WorkspaceID: workspaceID,
		ActorID:     actor.ID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return db.ErrWorkspaceNotAccessible
	}
	if err != nil {
		return err
	}
	if !db.HasPermission(role, perm) {
		return db.ErrPermissionDenied
	}
	return nil
}
