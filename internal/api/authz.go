package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nokku-sh/nokku/internal/iam"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
)

// ProcedurePermissions maps every workspace-scoped procedure to the single
// permission it requires. This is the only place permission codes are
// resolved from a procedure. Handlers run their data access with plain
// WithWorkspace. Procedures that need a different rule (user-scoped, public,
// token-scoped, owner-only, streaming, or handler-level logic) are not listed
// here and keep their existing handler checks.
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
	nokkuv1connect.DaemonServiceGetDaemonProcedure:          db.PermDaemonsView,
	nokkuv1connect.DaemonServiceListDaemonsProcedure:        db.PermDaemonsView,
	nokkuv1connect.DaemonServiceListSessionsProcedure:       db.PermDaemonsView,
	nokkuv1connect.DaemonServiceCreateSessionProcedure:      db.PermDaemonsView,
	nokkuv1connect.DaemonServiceUpdateDaemonProcedure:       db.PermDaemonsEdit,
	nokkuv1connect.DaemonServiceDeleteDaemonProcedure:       db.PermDaemonsEdit,
	nokkuv1connect.DaemonServiceRefreshEnrollTokenProcedure: db.PermSettingsEdit,
	nokkuv1connect.DaemonServiceRevokeEnrollTokenProcedure:  db.PermSettingsEdit,

	// Invitations
	nokkuv1connect.InvitationServiceRefreshInviteTokenProcedure: db.PermSettingsEdit,
	nokkuv1connect.InvitationServiceRevokeInviteTokenProcedure:  db.PermSettingsEdit,

	// Principals
	nokkuv1connect.PrincipalServiceListPrincipalsProcedure:              db.PermPrincipalsView,
	nokkuv1connect.PrincipalServiceSetPrincipalsProcedure:               db.PermPrincipalsEdit,
	nokkuv1connect.PrincipalServiceAddSubjectsToPrincipalProcedure:      db.PermPrincipalsEdit,
	nokkuv1connect.PrincipalServiceRemoveSubjectsFromPrincipalProcedure: db.PermPrincipalsEdit,
	nokkuv1connect.PrincipalServiceRevokeAllAccessProcedure:             db.PermPrincipalsEdit,

	// Service accounts
	nokkuv1connect.ServiceAccountServiceGetServiceAccountProcedure:    db.PermServiceAccountsView,
	nokkuv1connect.ServiceAccountServiceListServiceAccountsProcedure:  db.PermServiceAccountsView,
	nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure: db.PermServiceAccountsEdit,
	nokkuv1connect.ServiceAccountServiceUpdateServiceAccountProcedure: db.PermServiceAccountsEdit,
	nokkuv1connect.ServiceAccountServiceDeleteServiceAccountProcedure: db.PermServiceAccountsEdit,

	// SSO
	nokkuv1connect.SSOServiceGetSSOProviderProcedure:    db.PermSsoView,
	nokkuv1connect.SSOServiceUpdateSSOProviderProcedure: db.PermSsoEdit,

	// Targets
	nokkuv1connect.TargetServiceGetTargetProcedure:        db.PermTargetsView,
	nokkuv1connect.TargetServiceListTargetsProcedure:      db.PermTargetsView,
	nokkuv1connect.TargetServiceGetSubjectAccessProcedure: db.PermTargetsView,
	nokkuv1connect.TargetServiceGetTargetFiltersProcedure: db.PermTargetsView,
	nokkuv1connect.TargetServiceCreateTargetProcedure:     db.PermTargetsEdit,
	nokkuv1connect.TargetServiceUpdateTargetProcedure:     db.PermTargetsEdit,
	nokkuv1connect.TargetServiceDeleteTargetProcedure:     db.PermTargetsEdit,

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
		perm, ok := ProcedurePermissions[req.Spec().Procedure]
		if !ok {
			return next(ctx, req)
		}

		if err := a.authorize(ctx, perm); err != nil {
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
	return next
}

// authorize resolves the actor's current role in the pinned workspace and
// checks it against the permission. Daemons always act with the fixed
// "daemon" role. It runs as a single admin-pool query so it never opens the
// data transaction or sets RLS state.
func (a *AuthorizationInterceptor) authorize(
	ctx context.Context,
	perm db.Permission,
) error {
	return actorHasPermission(ctx, a.cfg.Conn, perm)
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

	role := "daemon"
	if actor.Kind != iam.KindDaemon {
		workspaceID := iam.WorkspaceIDFromContext(ctx)
		if workspaceID == "" {
			return db.ErrWorkspaceNotPinned
		}

		var err error
		role, err = actorRole(ctx, conn.AdminPool, workspaceID, actor.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return db.ErrWorkspaceNotAccessible
		}
		if err != nil {
			return err
		}
	}

	if !db.HasPermission(role, perm) {
		return db.ErrPermissionDenied
	}
	return nil
}

// actorRole returns the workspace role of a user or service account. It must
// run against a connection that bypasses RLS (the admin pool), because it
// resolves membership for a workspace that is not yet pinned for data access.
func actorRole(
	ctx context.Context,
	pool *pgxpool.Pool,
	workspaceID, actorID string,
) (string, error) {
	var role string
	err := pool.QueryRow(
		ctx,
		`SELECT role_name FROM workspace_members
		 WHERE workspace_id = $1 AND user_id = $2::uuid
		 UNION ALL
		 SELECT role_name FROM service_accounts
		 WHERE workspace_id = $1 AND id = $2::uuid
		 LIMIT 1`,
		workspaceID,
		actorID,
	).Scan(&role)
	return role, err
}
