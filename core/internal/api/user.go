package api

import (
	"context"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type userService struct {
	cfg *app.Config
}

func (s *userService) ListUsers(
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

func (s *userService) GetUser(
	ctx context.Context,
	req *nokkuv1.GetUserRequest,
) (*nokkuv1.GetUserResponse, error) {
	u, err := s.cfg.Conn.Tenant().GetUser(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &nokkuv1.GetUserResponse{User: u.ToProto()}, nil
}

// SetUserRole never touches the owner, see TransferOwnership.
func (s *userService) SetUserRole(
	ctx context.Context,
	req *nokkuv1.SetUserRoleRequest,
) (*nokkuv1.SetUserRoleResponse, error) {
	if !db.CanAssign(callerRole(ctx), req.GetRole()) {
		return nil, connect.NewError(connect.CodePermissionDenied, "role cannot be assigned by you")
	}
	audit.Set(ctx, "role", db.RoleLabel(req.GetRole()))
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetId()); err != nil {
			return err
		}
		if err := auditName(ctx, q, "name", req.GetId()); err != nil {
			return err
		}
		return q.UpdateUserRole(
			ctx,
			&db.UpdateUserRoleParams{ID: req.GetId(), Role: req.GetRole()},
		)
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.SetUserRoleResponse{}, nil
}

// DeactivateUser ends the user's sessions. Grants stay for a return.
func (s *userService) DeactivateUser(
	ctx context.Context,
	req *nokkuv1.DeactivateUserRequest,
) (*nokkuv1.DeactivateUserResponse, error) {
	if err := s.setUserActive(ctx, req.GetId(), false); err != nil {
		return nil, err
	}
	if _, err := s.cfg.IAM.RevokeUser(ctx, req.GetId()); err != nil {
		return nil, err
	}
	return &nokkuv1.DeactivateUserResponse{}, nil
}

func (s *userService) ReactivateUser(
	ctx context.Context,
	req *nokkuv1.ReactivateUserRequest,
) (*nokkuv1.ReactivateUserResponse, error) {
	if err := s.setUserActive(ctx, req.GetId(), true); err != nil {
		return nil, err
	}
	return &nokkuv1.ReactivateUserResponse{}, nil
}

func (s *userService) setUserActive(ctx context.Context, userID string, active bool) error {
	// The same actions SCIM records, so the log reads the same whoever did it.
	action := "UserDeactivated"
	if active {
		action = "UserActivated"
	}
	audit.SetAction(ctx, action)
	return s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, userID); err != nil {
			return err
		}
		if err := auditName(ctx, q, "name", userID); err != nil {
			return err
		}
		_, err := s.cfg.IAM.SetUserActive(ctx, q, userID, active)
		return err
	})
}

// DeleteUser takes the user's grants and team seats with them.
func (s *userService) DeleteUser(
	ctx context.Context,
	req *nokkuv1.DeleteUserRequest,
) (*nokkuv1.DeleteUserResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetId()); err != nil {
			return err
		}
		if err := auditName(ctx, q, "name", req.GetId()); err != nil {
			return err
		}
		return q.DeleteUser(ctx, req.GetId())
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteUserResponse{}, nil
}

// ClearUserIdentities also signs out, a wrong link must not keep its session.
func (s *userService) ClearUserIdentities(
	ctx context.Context,
	req *nokkuv1.ClearUserIdentitiesRequest,
) (*nokkuv1.ClearUserIdentitiesResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageUser(ctx, q, req.GetId()); err != nil {
			return err
		}
		return q.DeleteUserOIDCCredentials(ctx, req.GetId())
	}); err != nil {
		return nil, err
	}
	if _, err := s.cfg.IAM.RevokeUser(ctx, req.GetId()); err != nil {
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
func (s *userService) TransferOwnership(
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
