package api

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/email"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/tenant"
)

const findMailTimeout = 30 * time.Second

// Only CreateWorkspace and FindWorkspaces run outside the workspace of the request's host.
type workspaceService struct {
	cfg *config.Config
}

func (s *workspaceService) GetWorkspace(
	ctx context.Context,
	_ *nokkuv1.GetWorkspaceRequest,
) (*nokkuv1.GetWorkspaceResponse, error) {
	workspace, err := s.cfg.Conn.Tenant().GetWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	ws, _ := actor.WorkspaceFromContext(ctx)
	// A failed lookup is Community, which leaves the banner out.
	st, _ := s.cfg.Entitlements.Status(ctx, ws.ID)
	resp := &nokkuv1.GetWorkspaceResponse{
		Workspace: workspace.ToProto(),
		BaseUrl:   new(ws.BaseURL),
		Inactive:  new(st.Plan.Name == entitlement.PlanInactive),
		Features:  featuresProto(st.Plan),
		Catalog:   catalogProto(),
		PlanNames: entitlement.PlanNames,
	}
	if st.Row != nil && s.cfg.SaaS {
		resp.DeleteAt = db.SafeTimestamp(deletionDate(st.Row))
	}
	return resp, nil
}

func (s *workspaceService) UpdateWorkspace(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceRequest,
) (*nokkuv1.UpdateWorkspaceResponse, error) {
	if _, err := applyMask(req, req.GetUpdateMask()); err != nil {
		return nil, err
	}
	var workspace *db.Workspace
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		// Locked, so two tabs saving different settings at once keep both.
		base, err := q.GetWorkspaceForUpdate(ctx)
		if err != nil {
			return err
		}
		wasEnforced := base.Settings.GetEnforceSso()
		if req.GetSettings() != nil {
			base.Settings = cmp.Or(base.Settings, &nokkuv1.WorkspaceSettings{})
			mergeSet(base.Settings.ProtoReflect(), req.GetSettings().ProtoReflect())
		}
		if !wasEnforced && base.Settings.GetEnforceSso() {
			has, err := iam.HasSSOProvider(ctx, q)
			if err != nil {
				return err
			}
			if !has {
				return connect.NewError(
					connect.CodeFailedPrecondition,
					"add and enable a provider before requiring single sign-on",
				)
			}
		}
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
			Name:        req.Name,
			Description: req.Description,
			Settings:    base.Settings,
		})
		if err != nil || wasEnforced || !base.Settings.GetEnforceSso() {
			return err
		}
		// A passkey session would outlive the rule by up to 30 days otherwise.
		ended, err := q.DeleteNonSSOSessions(ctx)
		if err != nil {
			return err
		}
		audit.Set(ctx, "sessions_ended", ended)
		// The ones that stay get what a new session gets from now on.
		_, err = q.CapSessions(ctx, time.Now().Add(iam.SSOSessionTTL))
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.UpdateWorkspaceResponse{Workspace: workspace.ToProto()}, nil
}

func (s *workspaceService) UpdateDaemonDefaults(
	ctx context.Context,
	req *nokkuv1.UpdateDaemonDefaultsRequest,
) (*nokkuv1.UpdateDaemonDefaultsResponse, error) {
	if _, err := applyMask(req, req.GetUpdateMask()); err != nil {
		return nil, err
	}
	var workspace *db.Workspace
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		// Locked like UpdateWorkspace, both write the same settings.
		base, err := q.GetWorkspaceForUpdate(ctx)
		if err != nil {
			return err
		}
		base.Settings = cmp.Or(base.Settings, &nokkuv1.WorkspaceSettings{})
		mergeSet(base.Settings.ProtoReflect(), (&nokkuv1.WorkspaceSettings{
			DefaultDaemonConfig: req.GetDefaultDaemonConfig(),
			SessionIdleTimeout:  req.GetSessionIdleTimeout(),
		}).ProtoReflect())
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{Settings: base.Settings})
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.UpdateDaemonDefaultsResponse{Workspace: workspace.ToProto()}, nil
}

// DeleteWorkspace is hosted only, a self-hosted server serves nothing else.
func (s *workspaceService) DeleteWorkspace(
	ctx context.Context,
	_ *nokkuv1.DeleteWorkspaceRequest,
) (*nokkuv1.DeleteWorkspaceResponse, error) {
	if !s.cfg.SaaS {
		return nil, errSingleWorkspace
	}
	ws, _ := actor.WorkspaceFromContext(ctx)
	if err := deleteWorkspace(ctx, s.cfg, ws); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteWorkspaceResponse{}, nil
}

// FindWorkspaces mails an address the workspaces it can sign in to. It answers
// the same whether there are any, so it names no account and no customer.
func (s *workspaceService) FindWorkspaces(
	ctx context.Context,
	req *nokkuv1.FindWorkspacesRequest,
) (*nokkuv1.FindWorkspacesResponse, error) {
	if !s.cfg.SaaS || actor.WorkspaceIDFromContext(ctx) != "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "workspaces are only found on the root host")
	}
	addr := iam.NormalizeEmail(req.GetEmail())
	// Detached, so timing never shows if the address has an account.
	mailCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), findMailTimeout)
	go func() {
		defer cancel()
		if err := s.mailWorkspaces(mailCtx, addr); err != nil && !errors.Is(err, email.ErrCooldown) {
			slog.Warn("workspaces mail not sent", "error", err)
		}
	}()
	return &nokkuv1.FindWorkspacesResponse{}, nil
}

func (s *workspaceService) mailWorkspaces(ctx context.Context, addr string) error {
	rows, err := s.cfg.Conn.Sys().ListWorkspacesByEmail(ctx, addr)
	if err != nil || len(rows) == 0 {
		return err
	}
	list := make([]email.WorkspaceLink, len(rows))
	for i, row := range rows {
		list[i] = email.WorkspaceLink{Name: row.Name, URL: s.cfg.Tenant.BaseURL(row.Slug)}
	}
	return s.cfg.Email.SendWorkspacesEmail(ctx, addr, list)
}

// A deleted workspace's recording objects go through the delete queue.
func deleteWorkspace(ctx context.Context, cfg *config.Config, ws actor.Workspace) error {
	ctx = actor.WithWorkspace(ctx, ws)
	if err := cfg.Conn.Tenant().DeleteWorkspace(ctx, ws.ID); err != nil {
		return err
	}
	cfg.Tenant.Forget(ws.Slug)
	return nil
}

// CreateWorkspace is the hosted signup, undone if the sign-in link goes unused.
func (s *workspaceService) CreateWorkspace(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceRequest,
) (*nokkuv1.CreateWorkspaceResponse, error) {
	if !s.cfg.SaaS || actor.WorkspaceIDFromContext(ctx) != "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "signup only happens on the root host")
	}
	if tenant.Forbidden(req.GetSlug()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, "this name is not available")
	}
	// Checked first, a workspace whose owner gets no mail sits until the purge.
	addr := iam.NormalizeEmail(req.GetOwnerEmail())
	if s.cfg.Email.OwnerLinkOnCooldown(addr) {
		return nil, connect.NewError(
			connect.CodeResourceExhausted,
			"a sign-in link went to this address a moment ago, try again later",
		)
	}
	if err := email.Verify(ctx, addr, true); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "please enter a valid email address")
	}
	ws, err := tenant.Create(ctx, s.cfg.Conn, s.cfg.Keyset, req.GetSlug(), strings.TrimSpace(req.GetName()),
		entitlement.TrialDays)
	if db.IsUniqueViolation(err) {
		return nil, connect.NewError(connect.CodeAlreadyExists, "this name is taken")
	}
	if err != nil {
		return nil, err
	}
	// A request racing the purge may have cached the slug's last owner.
	s.cfg.Tenant.Forget(ws.Slug)

	wsCtx := actor.WithWorkspace(ctx, actor.Workspace{
		ID: ws.ID, Slug: ws.Slug, BaseURL: s.cfg.Tenant.BaseURL(ws.Slug),
	})
	owner, err := s.cfg.IAM.CreateOwner(wsCtx, addr, req.GetOwnerName())
	if err != nil {
		return nil, err
	}
	link, err := s.cfg.IAM.IssueBootstrapLink(wsCtx, owner)
	if err != nil {
		return nil, err
	}
	if err := s.cfg.Email.SendOwnerLinkEmail(ctx, addr, link, iam.BootstrapTTL); err != nil {
		slog.Error("signup mail not sent", "error", err, "workspace_id", ws.ID)
		return nil, errMailNotSent
	}
	// The call is public, so the audit interceptor has no actor for it.
	s.cfg.Audit.Record(wsCtx, &audit.Event{
		Action:    "CreateWorkspace",
		ActorID:   owner.ID,
		ActorKind: string(actor.KindUser),
		ActorName: addr,
		Target:    ws.ID,
		OK:        true,
	})
	return &nokkuv1.CreateWorkspaceResponse{Url: new(s.cfg.Tenant.BaseURL(ws.Slug))}, nil
}

func (s *workspaceService) ListUsers(
	ctx context.Context,
	req *nokkuv1.ListUsersRequest,
) (*nokkuv1.ListUsersResponse, error) {
	q := s.cfg.Conn.Tenant()
	params := &db.ListUsersParams{
		Query:  req.Query,
		Role:   req.GetRole(),
		Limit:  req.Limit,
		Offset: req.Offset,
	}
	rows, err := q.ListUsers(ctx, params)
	if err != nil {
		return nil, err
	}
	counted := rows
	if len(rows) == 0 && req.GetOffset() > 0 {
		// A page past the end has no row to carry the total, the first row does.
		params.Limit, params.Offset = new(int32(1)), nil
		if counted, err = q.ListUsers(ctx, params); err != nil {
			return nil, err
		}
	}
	var total int32
	if len(counted) > 0 {
		total = counted[0].TotalCount
	}
	return &nokkuv1.ListUsersResponse{Users: db.UsersToProto(rows), Total: &total}, nil
}

func (s *workspaceService) GetUser(
	ctx context.Context,
	req *nokkuv1.GetUserRequest,
) (*nokkuv1.GetUserResponse, error) {
	u, err := s.cfg.Conn.Tenant().GetUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	return &nokkuv1.GetUserResponse{User: u.ToProto()}, nil
}

// UpdateUserRole never touches the owner, see TransferOwnership.
func (s *workspaceService) UpdateUserRole(
	ctx context.Context,
	req *nokkuv1.UpdateUserRoleRequest,
) (*nokkuv1.UpdateUserRoleResponse, error) {
	if !db.CanAssign(callerRole(ctx), req.GetRole()) {
		return nil, connect.NewError(connect.CodePermissionDenied, "role cannot be assigned by you")
	}
	audit.Set(ctx, "role", db.RoleLabel(req.GetRole()))
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetUserId()); err != nil {
			return err
		}
		if err := auditName(ctx, q, "name", req.GetUserId()); err != nil {
			return err
		}
		return q.UpdateUserRole(
			ctx,
			&db.UpdateUserRoleParams{ID: req.GetUserId(), Role: req.GetRole()},
		)
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.UpdateUserRoleResponse{}, nil
}

// SetUserActive ends a deactivated user's sessions. Grants stay for a return.
func (s *workspaceService) SetUserActive(
	ctx context.Context,
	req *nokkuv1.SetUserActiveRequest,
) (*nokkuv1.SetUserActiveResponse, error) {
	// The same actions SCIM records, so the log reads the same whoever did it.
	action := "UserDeactivated"
	if req.GetActive() {
		action = "UserActivated"
	}
	audit.SetAction(ctx, action)
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetUserId()); err != nil {
			return err
		}
		if err := auditName(ctx, q, "name", req.GetUserId()); err != nil {
			return err
		}
		_, err := s.cfg.IAM.SetUserActive(ctx, q, req.GetUserId(), req.GetActive())
		return err
	}); err != nil {
		return nil, err
	}
	if !req.GetActive() {
		if _, err := s.cfg.IAM.RevokeUser(ctx, req.GetUserId()); err != nil {
			return nil, err
		}
	}
	return &nokkuv1.SetUserActiveResponse{}, nil
}

// DeleteUser takes the user's grants and team seats with them.
func (s *workspaceService) DeleteUser(
	ctx context.Context,
	req *nokkuv1.DeleteUserRequest,
) (*nokkuv1.DeleteUserResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetUserId()); err != nil {
			return err
		}
		if err := auditName(ctx, q, "name", req.GetUserId()); err != nil {
			return err
		}
		return q.DeleteUser(ctx, req.GetUserId())
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteUserResponse{}, nil
}

// ClearUserIdentities also signs out, a wrong link must not keep its session.
func (s *workspaceService) ClearUserIdentities(
	ctx context.Context,
	req *nokkuv1.ClearUserIdentitiesRequest,
) (*nokkuv1.ClearUserIdentitiesResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetUserId()); err != nil {
			return err
		}
		return q.DeleteUserOIDCCredentials(ctx, req.GetUserId())
	}); err != nil {
		return nil, err
	}
	if _, err := s.cfg.IAM.RevokeUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	return &nokkuv1.ClearUserIdentitiesResponse{}, nil
}

// checkCanManageUser also protects the owner.
func checkCanManageUser(ctx context.Context, q *db.Queries, userID string) error {
	if userID == actor.UserIDFromContext(ctx) {
		return connect.NewError(connect.CodeFailedPrecondition, "you cannot change your own account here")
	}
	u, err := q.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if !db.CanAssign(callerRole(ctx), u.Role) {
		return db.ErrPermissionDenied
	}
	return nil
}

// TransferOwnership makes the caller an admin.
func (s *workspaceService) TransferOwnership(
	ctx context.Context,
	req *nokkuv1.TransferOwnershipRequest,
) (*nokkuv1.TransferOwnershipResponse, error) {
	if req.GetNewOwnerId() == actor.UserIDFromContext(ctx) {
		return nil, connect.NewError(connect.CodeInvalidArgument, "you are the owner already")
	}
	// With no new owner, the rollback gives the old one the role back.
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		ok, err := q.TransferOwnership(ctx, req.GetNewOwnerId())
		if err != nil {
			return err
		}
		if !ok {
			return connect.NewError(connect.CodeNotFound, "the new owner must be an active user of this workspace")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.TransferOwnershipResponse{}, nil
}
