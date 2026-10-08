package api

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	"github.com/nokku-sh/nokku/internal/tenant"
)

// workspaceService manages the workspace of the request's host and the
// users in it. CreateWorkspace is the one call that runs outside one, on
// the hosted service's root host.
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
	result := workspace.ToProto()
	// The webhook secret signs events to the customer's SIEM, only the
	// owner manages it and reads it back.
	if settings := result.GetSettings(); settings != nil &&
		callerRole(ctx) < nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER {
		settings.AuditWebhookUrl, settings.AuditWebhookSecret = nil, nil
	}
	return &nokkuv1.GetWorkspaceResponse{Workspace: result}, nil
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

// DeleteWorkspace only exists on the hosted service, a self-hosted server
// has nothing else to serve.
func (s *workspaceService) DeleteWorkspace(
	ctx context.Context,
	_ *nokkuv1.DeleteWorkspaceRequest,
) (*nokkuv1.DeleteWorkspaceResponse, error) {
	if !s.cfg.SaaS {
		return nil, errSingleWorkspace
	}
	ws := actor.WorkspaceIDFromContext(ctx)
	if err := s.cfg.Billing.Cancel(ctx, ws, true, ""); err != nil {
		return nil, errInternal
	}
	if err := s.cfg.Conn.Tenant().DeleteWorkspace(ctx, ws); err != nil {
		return nil, err
	}
	s.cfg.Record.PurgeWorkspace(ctx, ws)
	return &nokkuv1.DeleteWorkspaceResponse{}, nil
}

// CreateWorkspace is the hosted signup. The owner gets a sign-in link to the
// new workspace's host, the workspace is deleted again when nobody uses it.
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
	// Asked before anything exists, DNS included. A workspace whose owner
	// gets no mail would sit there until the purge.
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
	audit.SetTarget(ctx, ws.ID)

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
	if err := s.cfg.Email.SendOwnerLinkEmail(ctx, addr, link, (24 * time.Hour).String()); err != nil {
		slog.Error("signup mail not sent", "error", err, "workspace_id", ws.ID)
		return nil, errMailNotSent
	}
	return &nokkuv1.CreateWorkspaceResponse{Url: new(s.cfg.Tenant.BaseURL(ws.Slug))}, nil
}

// Users ----------------------------------------------------------------------

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

// SetUserActive ends the user's sessions on a deactivation. Grants stay, so
// switching the account back on restores its access.
func (s *workspaceService) SetUserActive(
	ctx context.Context,
	req *nokkuv1.SetUserActiveRequest,
) (*nokkuv1.SetUserActiveResponse, error) {
	audit.Set(ctx, "active", req.GetActive())
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetUserId()); err != nil {
			return err
		}
		return q.SetUserActive(
			ctx,
			&db.SetUserActiveParams{ID: req.GetUserId(), Active: req.GetActive()},
		)
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
		return q.DeleteUser(ctx, req.GetUserId())
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteUserResponse{}, nil
}

// checkCanManageUser also protects the owner, who is above everyone, and
// keeps people from managing themselves.
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
	// A transaction on purpose. When the new owner does not exist the update
	// already took the old one's role, and the rollback gives it back.
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		n, err := q.TransferOwnership(ctx, req.GetNewOwnerId())
		if err != nil {
			return err
		}
		// One row means only the old owner changed, the new one does not exist.
		if n != 2 {
			return newError(connect.CodeNotFound, "the new owner must be an active user of this workspace")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.TransferOwnershipResponse{}, nil
}

// streamLife ends a stream so the client comes back through authentication.
// A session that ended meanwhile hears hints until then, never data.
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
