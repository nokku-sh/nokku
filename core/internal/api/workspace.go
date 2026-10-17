package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

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

// workspaceService serves the workspace of the request's host. Only CreateWorkspace runs outside one.
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
	}
	if st.Sub != nil {
		resp.DeleteAt = db.SafeTimestamp(deletionDate(st.Sub))
	}
	return resp, nil
}

func (s *workspaceService) UpdateWorkspace(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceRequest,
) (*nokkuv1.UpdateWorkspaceResponse, error) {
	var workspace *db.Workspace
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		base, err := q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		proto.Merge(base.Settings, req.GetSettings())
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
			Name:        req.Name,
			Description: req.Description,
			Settings:    base.Settings,
		})
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.UpdateWorkspaceResponse{Workspace: workspace.ToProto()}, nil
}

// DeleteWorkspace only exists on the hosted service, a self-hosted server has nothing else to serve.
func (s *workspaceService) DeleteWorkspace(
	ctx context.Context,
	_ *nokkuv1.DeleteWorkspaceRequest,
) (*nokkuv1.DeleteWorkspaceResponse, error) {
	if !s.cfg.SaaS {
		return nil, errSingleWorkspace
	}
	ws, _ := actor.WorkspaceFromContext(ctx)
	if err := s.cfg.Billing.Cancel(ctx, ws.ID, true, ""); err != nil {
		return nil, errInternal
	}
	if err := deleteWorkspace(ctx, s.cfg, ws); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteWorkspaceResponse{}, nil
}

// deleteWorkspace removes ws with its recordings and avatars.
func deleteWorkspace(ctx context.Context, cfg *config.Config, ws actor.Workspace) error {
	ctx = actor.WithWorkspace(ctx, ws)
	// Avatars are stored by user id, so the ids are read while the rows exist.
	userIDs, err := cfg.Conn.Tenant().ListUserIDs(ctx)
	if err != nil {
		return err
	}
	if err := cfg.Conn.Tenant().DeleteWorkspace(ctx, ws.ID); err != nil {
		return err
	}
	cfg.Tenant.Forget(ws.Slug)
	cfg.Record.PurgeWorkspace(ctx, ws.ID)

	// Detached like PurgeWorkspace, a big workspace would outlast the request.
	avatarCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	go func() {
		defer cancel()
		for _, id := range userIDs {
			deleteAvatar(avatarCtx, cfg, id)
		}
	}()
	return nil
}

// CreateWorkspace is the hosted signup. The workspace is deleted again when nobody uses the sign-in link.
func (s *workspaceService) CreateWorkspace(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceRequest,
) (*nokkuv1.CreateWorkspaceResponse, error) {
	if !s.cfg.SaaS || actor.WorkspaceIDFromContext(ctx) != "" {
		return nil, newError(connect.CodeFailedPrecondition, "signup only happens on the root host")
	}
	if tenant.Forbidden(req.GetSlug()) {
		return nil, newError(connect.CodeInvalidArgument, "this name is not available")
	}
	// Asked before anything exists. A workspace whose owner gets no mail would sit there until the purge.
	addr := strings.ToLower(strings.TrimSpace(req.GetOwnerEmail()))
	if s.cfg.Email.OwnerLinkOnCooldown(ctx, addr) {
		return nil, newError(
			connect.CodeResourceExhausted,
			"a sign-in link went to this address a moment ago, try again later",
		)
	}
	if err := email.Verify(ctx, addr, true); err != nil {
		return nil, newError(connect.CodeInvalidArgument, "please enter a valid email address")
	}
	ws, err := tenant.Create(ctx, s.cfg.Conn, req.GetSlug(), strings.TrimSpace(req.GetName()))
	if db.IsUniqueViolation(err) {
		return nil, newError(connect.CodeAlreadyExists, "this name is taken")
	}
	if err != nil {
		return nil, err
	}

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
	rows, err := s.cfg.Conn.Tenant().ListUsers(ctx, &db.ListUsersParams{
		Query:  req.Query,
		Role:   req.GetRole(),
		Limit:  req.Limit,
		Offset: req.Offset,
	})
	if err != nil {
		return nil, err
	}
	var total int32
	if len(rows) > 0 {
		total = rows[0].TotalCount
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
		return nil, newError(connect.CodePermissionDenied, "role cannot be assigned by you")
	}
	audit.Set(ctx, "role", db.RoleLabel(req.GetRole()))
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetUserId()); err != nil {
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

// SetUserActive ends the user's sessions on a deactivation. Grants stay, so switching back on restores access.
func (s *workspaceService) SetUserActive(
	ctx context.Context,
	req *nokkuv1.SetUserActiveRequest,
) (*nokkuv1.SetUserActiveResponse, error) {
	audit.Set(ctx, "active", req.GetActive())
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetUserId()); err != nil {
			return err
		}
		_, err := s.cfg.IAM.SetUserActive(ctx, q, req.GetUserId(), req.GetActive())
		return err
	}); err != nil {
		if errors.Is(err, iam.ErrSeatLimit) {
			return nil, errSeatLimit
		}
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
		return q.DeleteUser(ctx, req.GetUserId())
	}); err != nil {
		return nil, err
	}
	deleteAvatar(ctx, s.cfg, req.GetUserId())
	return &nokkuv1.DeleteUserResponse{}, nil
}

// checkCanManageUser also protects the owner, and keeps people from managing themselves.
func checkCanManageUser(ctx context.Context, q *db.Queries, userID string) error {
	if userID == actor.UserIDFromContext(ctx) {
		return newError(connect.CodeFailedPrecondition, "you cannot change your own account here")
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
		return nil, newError(connect.CodeInvalidArgument, "you are the owner already")
	}
	// A transaction on purpose. A missing new owner means the old one already lost the role, the rollback gives it back.
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		ok, err := q.TransferOwnership(ctx, req.GetNewOwnerId())
		if err != nil {
			return err
		}
		if !ok {
			return newError(connect.CodeNotFound, "the new owner must be an active user of this workspace")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.TransferOwnershipResponse{}, nil
}

// streamLife ends a stream so the client comes back through authentication.
const streamLife = 10 * time.Minute

// SubscribeChanges costs a goroutine per stream and no database connection.
func (s *workspaceService) SubscribeChanges(
	ctx context.Context,
	_ *nokkuv1.SubscribeChangesRequest,
	stream *connect.ServerStream[nokkuv1.SubscribeChangesResponse],
) error {
	ctx, cancel := context.WithTimeout(ctx, streamLife)
	defer cancel()
	sub := s.cfg.Live.Subscribe(actor.WorkspaceIDFromContext(ctx))
	defer sub.Close()

	// Without a first message the client cannot tell when it is subscribed.
	if err := stream.Send(&nokkuv1.SubscribeChangesResponse{}); err != nil {
		return err
	}
	for {
		change, err := sub.Next(ctx)
		if err != nil {
			return nil
		}
		res := &nokkuv1.SubscribeChangesResponse{Services: change.Services}
		if change.Everything {
			res.Everything = new(true)
		}
		if err := stream.Send(res); err != nil {
			return err
		}
	}
}
