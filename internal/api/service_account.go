package api

import (
	"cmp"
	"context"
	"time"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

type serviceAccountService struct {
	cfg *config.Config
}

func newServiceAccountService(cfg *config.Config) *serviceAccountService {
	return &serviceAccountService{cfg: cfg}
}

func (s *serviceAccountService) GetServiceAccount(
	ctx context.Context,
	req *nokkuv1.GetServiceAccountRequest,
) (*nokkuv1.GetServiceAccountResponse, error) {
	var result *db.ServiceAccount
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetServiceAccount(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.GetServiceAccountResponse{
		ServiceAccount: result.ToProto(),
	}, nil
}

func (s *serviceAccountService) CreateServiceAccount(
	ctx context.Context,
	req *nokkuv1.CreateServiceAccountRequest,
) (*nokkuv1.CreateServiceAccountResponse, error) {
	roleName := cmp.Or(req.GetRoleName(), string(db.RoleMember))
	if !callerRole(ctx).CanAssign(db.Role(roleName)) {
		return nil, newError(connect.CodePermissionDenied, "role cannot be granted by you")
	}

	raw, tokenHash, err := iam.NewAPIKey()
	if err != nil {
		return nil, errInternal
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		params := &db.CreateServiceAccountParams{
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.GetName(),
			Description: req.Description,
			Tags:        req.GetTags(),
			RoleName:    &roleName,
			TokenHash:   &tokenHash,
		}

		if req.GetExpiresAt() != nil && !req.GetExpiresAt().AsTime().IsZero() {
			expiry := req.GetExpiresAt().AsTime()
			if expiry.Before(time.Now()) {
				return newError(connect.CodeInvalidArgument, "expires_at must be in the future")
			}
			params.ExpiresAt = &expiry
		}

		saID, err := q.CreateServiceAccount(ctx, params)
		if err != nil {
			return err
		}
		result, err = q.GetServiceAccount(ctx, saID)
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.CreateServiceAccountResponse{
		ServiceAccount: result.ToProto(),
		Token:          &raw,
	}, nil
}

func (s *serviceAccountService) UpdateServiceAccount(
	ctx context.Context,
	req *nokkuv1.UpdateServiceAccountRequest,
) (*nokkuv1.UpdateServiceAccountResponse, error) {
	if req.RoleName != nil && !callerRole(ctx).CanAssign(db.Role(req.GetRoleName())) {
		return nil, newError(connect.CodePermissionDenied, "role cannot be granted by you")
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		if err := checkCanManageServiceAccount(ctx, q, req.GetId()); err != nil {
			return err
		}
		updatedID, err := q.UpdateServiceAccount(ctx, &db.UpdateServiceAccountParams{
			ServiceAccountID: req.GetId(),
			Name:             req.Name,
			Description:      req.Description,
			RoleName:         req.RoleName,
			Tags:             req.GetTags(),
		})
		if err != nil {
			return err
		}
		result, err = q.GetServiceAccount(ctx, updatedID)
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.UpdateServiceAccountResponse{
		ServiceAccount: result.ToProto(),
	}, nil
}

func (s *serviceAccountService) ListServiceAccounts(
	ctx context.Context,
	req *nokkuv1.ListServiceAccountsRequest,
) (*nokkuv1.ListServiceAccountsResponse, error) {
	var result []*db.ListServiceAccountsRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.ListServiceAccounts(ctx, &db.ListServiceAccountsParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			Tags:        req.GetTags(),
			RoleName:    req.RoleName,
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		return err
	}); err != nil {
		return nil, err
	}
	var count int32
	if len(result) > 0 {
		count = result[0].TotalCount
	}

	return &nokkuv1.ListServiceAccountsResponse{
		ServiceAccounts: db.ServiceAccountsToProto(result),
		Total:           &count,
	}, nil
}

func (s *serviceAccountService) DeleteServiceAccount(
	ctx context.Context,
	req *nokkuv1.DeleteServiceAccountRequest,
) (*nokkuv1.DeleteServiceAccountResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		if err := checkCanManageServiceAccount(ctx, q, req.GetId()); err != nil {
			return err
		}
		return q.DeleteServiceAccount(ctx, req.GetId())
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteServiceAccountResponse{}, nil
}

func checkCanManageServiceAccount(ctx context.Context, q db.Querier, id string) error {
	sa, err := q.GetServiceAccount(ctx, id)
	if err != nil {
		return err
	}
	if !callerRole(ctx).CanAssign(db.Role(sa.RoleName)) {
		return db.ErrPermissionDenied
	}
	return nil
}
