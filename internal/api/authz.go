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

// ProcedureRoles maps every workspace-scoped procedure to the least role that
// may call it. This is the only place a procedure's required role is
// resolved. Handlers run their data access with plain WithWorkspace.
var ProcedureRoles = map[string]db.Role{
	// Billing
	nokkuv1connect.BillingServiceGetBillingProcedure: db.RoleAdmin,

	// Certificate authorities. Members read them: nk trusts the X.509 CAs of
	// every workspace it belongs to.
	nokkuv1connect.CertificateServiceGetCertificateAuthorityProcedure:      db.RoleMember,
	nokkuv1connect.CertificateServiceListCertificateAuthoritiesProcedure:   db.RoleMember,
	nokkuv1connect.CertificateServiceCreateCertificateAuthorityProcedure:   db.RoleEditor,
	nokkuv1connect.CertificateServiceUpdateCertificateAuthorityProcedure:   db.RoleEditor,
	nokkuv1connect.CertificateServiceDeleteCertificateAuthorityProcedure:   db.RoleEditor,
	nokkuv1connect.CertificateServiceRolloverCertificateAuthorityProcedure: db.RoleEditor,

	// Daemons. A web session only opens the transport, sshd still checks the
	// certificate against the synced grants.
	nokkuv1connect.DaemonServiceCreateSessionProcedure: db.RoleMember,
	nokkuv1connect.DaemonServiceGetDaemonProcedure:     db.RoleViewer,
	nokkuv1connect.DaemonServiceListDaemonsProcedure:   db.RoleViewer,
	nokkuv1connect.DaemonServiceListSessionsProcedure:  db.RoleViewer,
	nokkuv1connect.DaemonServiceUpdateDaemonProcedure:  db.RoleEditor,
	nokkuv1connect.DaemonServiceDeleteDaemonProcedure:  db.RoleEditor,
	nokkuv1connect.DaemonServiceCloseSessionProcedure:  db.RoleEditor,

	// Join tokens (enroll and invite)
	nokkuv1connect.TokenServiceListTokensProcedure:  db.RoleViewer,
	nokkuv1connect.TokenServiceCreateTokenProcedure: db.RoleAdmin,
	nokkuv1connect.TokenServiceDeleteTokenProcedure: db.RoleAdmin,

	// Principals
	nokkuv1connect.PrincipalServiceListPrincipalsProcedure:              db.RoleViewer,
	nokkuv1connect.PrincipalServiceAddSubjectsToPrincipalProcedure:      db.RoleEditor,
	nokkuv1connect.PrincipalServiceRemoveSubjectsFromPrincipalProcedure: db.RoleEditor,
	nokkuv1connect.PrincipalServiceRevokeAllAccessProcedure:             db.RoleEditor,
	nokkuv1connect.PrincipalServiceAddPrincipalProcedure:                db.RoleEditor,
	nokkuv1connect.PrincipalServiceRemovePrincipalProcedure:             db.RoleEditor,

	// Service accounts
	nokkuv1connect.ServiceAccountServiceGetServiceAccountProcedure:    db.RoleViewer,
	nokkuv1connect.ServiceAccountServiceListServiceAccountsProcedure:  db.RoleViewer,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure: db.RoleEditor,
	nokkuv1connect.ServiceAccountServiceUpdateServiceAccountProcedure: db.RoleEditor,
	nokkuv1connect.ServiceAccountServiceDeleteServiceAccountProcedure: db.RoleEditor,

	// SSO
	nokkuv1connect.SSOServiceGetSSOProviderProcedure:    db.RoleViewer,
	nokkuv1connect.SSOServiceUpdateSSOProviderProcedure: db.RoleAdmin,

	// SCIM connector tokens (the endpoint itself is token-scoped)
	nokkuv1connect.SCIMServiceListSCIMTokensProcedure:  db.RoleViewer,
	nokkuv1connect.SCIMServiceCreateSCIMTokenProcedure: db.RoleAdmin,
	nokkuv1connect.SCIMServiceDeleteSCIMTokenProcedure: db.RoleAdmin,

	// Targets
	nokkuv1connect.TargetServiceGetTargetProcedure:           db.RoleViewer,
	nokkuv1connect.TargetServiceListTargetsProcedure:         db.RoleViewer,
	nokkuv1connect.TargetServiceGetSubjectAccessProcedure:    db.RoleViewer,
	nokkuv1connect.TargetServiceGetTargetFiltersProcedure:    db.RoleViewer,
	nokkuv1connect.TargetServiceGetTargetPrincipalsProcedure: db.RoleViewer,
	nokkuv1connect.TargetServiceCreateTargetProcedure:        db.RoleEditor,
	nokkuv1connect.TargetServiceUpdateTargetProcedure:        db.RoleEditor,
	nokkuv1connect.TargetServiceDeleteTargetProcedure:        db.RoleEditor,
	nokkuv1connect.TargetServiceSyncTargetUsersProcedure:     db.RoleEditor,

	// Teams
	nokkuv1connect.TeamServiceGetTeamProcedure:          db.RoleViewer,
	nokkuv1connect.TeamServiceListTeamsProcedure:        db.RoleViewer,
	nokkuv1connect.TeamServiceListTeamMembersProcedure:  db.RoleViewer,
	nokkuv1connect.TeamServiceListTeamsForUserProcedure: db.RoleViewer,
	nokkuv1connect.TeamServiceCreateTeamProcedure:       db.RoleEditor,
	nokkuv1connect.TeamServiceUpdateTeamProcedure:       db.RoleEditor,
	nokkuv1connect.TeamServiceDeleteTeamProcedure:       db.RoleEditor,
	nokkuv1connect.TeamServiceAddTeamMemberProcedure:    db.RoleEditor,
	nokkuv1connect.TeamServiceRemoveTeamMemberProcedure: db.RoleEditor,

	// Workspaces
	nokkuv1connect.WorkspaceServiceGetWorkspaceMemberProcedure:    db.RoleViewer,
	nokkuv1connect.WorkspaceServiceListWorkspaceMembersProcedure:  db.RoleViewer,
	nokkuv1connect.WorkspaceServiceUpdateWorkspaceMemberProcedure: db.RoleAdmin,
	nokkuv1connect.WorkspaceServiceRemoveWorkspaceMemberProcedure: db.RoleAdmin,
	nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure:       db.RoleAdmin,
	nokkuv1connect.WorkspaceServiceDeleteWorkspaceProcedure:       db.RoleOwner,

	// Workspace domains
	nokkuv1connect.WorkspaceDomainServiceGetWorkspaceDomainProcedure:             db.RoleViewer,
	nokkuv1connect.WorkspaceDomainServiceListWorkspaceDomainsProcedure:           db.RoleViewer,
	nokkuv1connect.WorkspaceDomainServiceCreateWorkspaceDomainProcedure:          db.RoleAdmin,
	nokkuv1connect.WorkspaceDomainServiceDeleteWorkspaceDomainProcedure:          db.RoleAdmin,
	nokkuv1connect.WorkspaceDomainServiceVerifyWorkspaceDomainProcedure:          db.RoleAdmin,
	nokkuv1connect.WorkspaceDomainServiceRegenerateWorkspaceDomainTokenProcedure: db.RoleAdmin,

	// Recordings
	nokkuv1connect.RecordingServiceListRecordingsProcedure:  db.RoleViewer,
	nokkuv1connect.RecordingServiceGetRecordingProcedure:    db.RoleViewer,
	nokkuv1connect.RecordingServiceDeleteRecordingProcedure: db.RoleEditor,

	// Audit
	nokkuv1connect.UtilServiceListAuditLogsProcedure:   db.RoleViewer,
	nokkuv1connect.UtilServiceExportAuditLogsProcedure: db.RoleViewer,
}

// personalProcedures take a workspace role only when a workspace is pinned.
// Without one they serve the caller's own rows, like the personal activity
// log, and the handler scopes the read to the caller.
var personalProcedures = map[string]struct{}{
	nokkuv1connect.UtilServiceListAuditLogsProcedure:   {},
	nokkuv1connect.UtilServiceExportAuditLogsProcedure: {},
}

// selfScopedProcedures are open to any authenticated user or service
// account. Each one is scoped to the caller (their account, their
// workspaces, their certs) or checks owner rights in the handler.
var selfScopedProcedures = map[string]struct{}{
	nokkuv1connect.AccountServiceChangePasswordProcedure:          {},
	nokkuv1connect.AccountServiceDeleteAccountProcedure:           {},
	nokkuv1connect.AccountServiceGetAccountProcedure:              {},
	nokkuv1connect.AccountServiceListAccountSessionsProcedure:     {},
	nokkuv1connect.AccountServiceListBackupCodesProcedure:         {},
	nokkuv1connect.AccountServiceListCredentialsProcedure:         {},
	nokkuv1connect.AccountServiceRemoveBackupCodesProcedure:       {},
	nokkuv1connect.AccountServiceRemoveCredentialProcedure:        {},
	nokkuv1connect.AccountServiceRemoveIdentityProcedure:          {},
	nokkuv1connect.AccountServiceRemovePasswordProcedure:          {},
	nokkuv1connect.AccountServiceRemoveSessionProcedure:           {},
	nokkuv1connect.AccountServiceRenameCredentialProcedure:        {},
	nokkuv1connect.AccountServiceRotateBackupCodesProcedure:       {},
	nokkuv1connect.AccountServiceUpdateAccountProcedure:           {},
	nokkuv1connect.BillingServiceCancelSubscriptionProcedure:      {},
	nokkuv1connect.BillingServiceCreateCheckoutProcedure:          {},
	nokkuv1connect.BillingServiceCreatePortalProcedure:            {},
	nokkuv1connect.BillingServiceGetLicenseProcedure:              {},
	nokkuv1connect.CertificateServiceSignSSHCertificateProcedure:  {},
	nokkuv1connect.CertificateServiceSignX509CertificateProcedure: {},
	nokkuv1connect.DaemonServiceRelayProcedure:                    {},
	nokkuv1connect.InvitationServiceAcceptInvitationProcedure:     {},
	nokkuv1connect.InvitationServiceGetInvitationProcedure:        {},
	nokkuv1connect.TargetServiceGetMyAccessProcedure:              {},
	nokkuv1connect.UtilServiceListRolesProcedure:                  {},
	nokkuv1connect.UtilServiceWhoamiProcedure:                     {},
	nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure:       {},
	nokkuv1connect.WorkspaceServiceGetWorkspaceProcedure:          {},
	nokkuv1connect.WorkspaceServiceListWorkspacesProcedure:        {},
	nokkuv1connect.WorkspaceServiceUpdateWorkspaceOwnerProcedure:  {},
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
	if role, ok := ProcedureRoles[procedure]; ok {
		if _, personal := personalProcedures[procedure]; personal && iam.WorkspaceIDFromContext(ctx) == "" {
			return ctx, nil
		}
		return actorHasRole(ctx, a.cfg.Conn, role)
	}
	if _, ok := selfScopedProcedures[procedure]; ok {
		return ctx, nil
	}
	if isPublicEndpoint(procedure) {
		return ctx, nil
	}
	return ctx, db.ErrPermissionDenied
}

// actorHasRole resolves the request actor's role in the pinned workspace and
// checks it against required. The returned context records the verified
// membership and role, so WithWorkspace and handlers skip another lookup.
func actorHasRole(
	ctx context.Context,
	conn *db.Connection,
	required db.Role,
) (context.Context, error) {
	actor, _ := iam.PrincipalFromContext(ctx)
	if actor.ID == "" {
		return ctx, db.ErrNoActor
	}
	workspaceID := iam.WorkspaceIDFromContext(ctx)
	if workspaceID == "" {
		return ctx, db.ErrWorkspaceNotPinned
	}
	role, err := conn.Sys().GetActorRole(ctx, &db.GetActorRoleParams{
		WorkspaceID: workspaceID,
		ActorID:     actor.ID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ctx, db.ErrWorkspaceNotAccessible
	}
	if err != nil {
		return ctx, err
	}
	if !db.Role(role).AtLeast(required) {
		return ctx, db.ErrPermissionDenied
	}
	return iam.WithMember(ctx, workspaceID, role), nil
}

// callerRole is the role authorization verified for this request.
func callerRole(ctx context.Context) db.Role {
	return db.Role(iam.MemberRole(ctx))
}
