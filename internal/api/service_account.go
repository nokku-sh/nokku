package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type ServiceAccountService struct {
	cfg *config.Config
}

func NewServiceAccountService(cfg *config.Config) *ServiceAccountService {
	return &ServiceAccountService{cfg: cfg}
}

func (s *ServiceAccountService) GetServiceAccount(
	ctx context.Context,
	req *nokkuv1.GetServiceAccountRequest,
) (*nokkuv1.GetServiceAccountResponse, error) {
	var result *db.ServiceAccount
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetServiceAccount(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if result == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.GetServiceAccountResponse{
		ServiceAccount: result.ToProto(),
	}, nil
}

func (s *ServiceAccountService) CreateServiceAccount(
	ctx context.Context,
	req *nokkuv1.CreateServiceAccountRequest,
) (*nokkuv1.CreateServiceAccountResponse, error) {
	if err := s.cfg.Billing.Check(
		ctx,
		req.GetWorkspaceId(),
		billing.ResourceServiceAccounts,
	); err != nil {
		return nil, err
	}

	roleName := req.GetRoleName()
	if roleName == "" {
		roleName = "viewer"
	}
	if !db.IsServiceAccountRole(roleName) {
		return nil, ErrInvalidInput
	}

	var result *db.ServiceAccount
	var key kagi.APIKey
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		id := uuid.NewString()
		params := &db.CreateServiceAccountParams{
			ID:          id,
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.GetName(),
			Description: req.Description,
			Tags:        req.GetTags(),
			RoleName:    &roleName,
		}

		if req.GetExpiresAt() != nil && !req.GetExpiresAt().AsTime().IsZero() {
			expiry := req.GetExpiresAt().AsTime()
			params.ExpiresAt = &expiry
		}

		result, err = q.CreateServiceAccount(ctx, params)
		if err != nil {
			return err
		}

		// The service account's credential is a kagi API key acting as the
		// service-account subject. Expiry is enforced by the key at
		// verification time, so a short-lived key is really short-lived.
		var ttl time.Duration
		if req.GetExpiresAt() != nil && !req.GetExpiresAt().AsTime().IsZero() {
			ttl = time.Until(req.GetExpiresAt().AsTime())
			if ttl <= 0 {
				return NewError(connect.CodeInvalidArgument, "expires_at must be in the future")
			}
		}
		key, err = s.cfg.Auth.APIKeys.Issue(
			ctx,
			kagi.TenantID(req.GetWorkspaceId()),
			id,
			auth.KindServiceAccount,
			req.GetName(),
			nil,
			ttl,
		)
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.CreateServiceAccountResponse{
		ServiceAccount: result.ToProto(),
		Token:          &key.FullKey,
	}, nil
}

func (s *ServiceAccountService) UpdateServiceAccount(
	ctx context.Context,
	req *nokkuv1.UpdateServiceAccountRequest,
) (*nokkuv1.UpdateServiceAccountResponse, error) {
	if req.RoleName != nil && !db.IsServiceAccountRole(req.GetRoleName()) {
		return nil, ErrInvalidInput
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.UpdateServiceAccount(ctx, &db.UpdateServiceAccountParams{
			ServiceAccountID: req.GetId(),
			Name:             req.Name,
			Description:      req.Description,
			RoleName:         req.RoleName,
		})
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}
	if result == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.UpdateServiceAccountResponse{
		ServiceAccount: result.ToProto(),
	}, nil
}

func (s *ServiceAccountService) ListServiceAccounts(
	ctx context.Context,
	req *nokkuv1.ListServiceAccountsRequest,
) (*nokkuv1.ListServiceAccountsResponse, error) {
	var result []*db.ListServiceAccountsRow
	count := int32(0)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		sas, err := q.ListServiceAccounts(ctx, &db.ListServiceAccountsParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			Tags:        req.GetTags(),
			RoleName:    req.RoleName,
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		if err != nil {
			return err
		}
		result = sas
		if len(sas) > 0 {
			count = sas[0].TotalCount
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.ListServiceAccountsResponse{
		ServiceAccounts: db.ServiceAccountsToProto(result),
		Total:           &count,
	}, nil
}

func (s *ServiceAccountService) DeleteServiceAccount(
	ctx context.Context,
	req *nokkuv1.DeleteServiceAccountRequest,
) (*nokkuv1.DeleteServiceAccountResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteServiceAccount(ctx, req.GetId())
	}); err != nil {
		return nil, DBError(err)
	}
	// Revoke every API key minted for the service account so its tokens stop
	// working immediately, not when they would have expired.
	_ = s.cfg.Auth.APIKeys.RevokeAll(ctx, kagi.TenantID(req.GetWorkspaceId()), req.GetId())
	return &nokkuv1.DeleteServiceAccountResponse{}, nil
}
