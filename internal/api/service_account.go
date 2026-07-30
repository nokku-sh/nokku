package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
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
		saID := req.GetId()
		if saID == "" {
			saID = meta.ServiceAccountIDFromContext(ctx) // actor might be service account
		}
		result, err = q.GetServiceAccount(ctx, saID)
		return err
	}); err != nil {
		return nil, ErrNotFound
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
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	if err := s.cfg.Entitlements.Check(
		ctx,
		req.GetWorkspaceId(),
		entitlement.ResourceServiceAccounts,
	); err != nil {
		return nil, err
	}

	token, err := crypto.NewServiceAccountToken()
	if err != nil {
		return nil, ErrInternal
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		params := &db.CreateServiceAccountParams{
			ID:          token.ID,
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.GetName(),
			Description: req.Description,
			Tags:        req.GetTags(),
			TokenHash:   token.Hash,
		}

		if req.GetExpiresAt() != nil && !req.GetExpiresAt().AsTime().IsZero() {
			expiry := req.GetExpiresAt().AsTime()
			params.ExpiresAt = &expiry
		}

		result, err = q.CreateServiceAccount(ctx, params)
		return err
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.CreateServiceAccountResponse{
		ServiceAccount: result.ToProto(),
		Token:          &token.Plaintext,
	}, nil
}

func (s *ServiceAccountService) UpdateServiceAccount(
	ctx context.Context,
	req *nokkuv1.UpdateServiceAccountRequest,
) (*nokkuv1.UpdateServiceAccountResponse, error) {
	var result *db.ServiceAccount
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.UpdateServiceAccount(ctx, &db.UpdateServiceAccountParams{
			ServiceAccountID: req.GetId(),
			Name:             req.Name,
			Description:      req.Description,
		})
		if err != nil {
			return err
		}
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return nil
	}); err != nil {
		return nil, ErrInternal
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
	var result []*nokkuv1.ServiceAccount
	var count int32
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		var err error
		count, err = q.CountServiceAccounts(ctx, &db.CountServiceAccountsParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			Tags:        req.GetTags(),
		})
		if err != nil {
			return err
		}
		sas, err := q.ListServiceAccounts(ctx, &db.ListServiceAccountsParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			Tags:        req.GetTags(),
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		if err != nil {
			return err
		}
		result = db.ServiceAccountsToProto(sas)
		return nil
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.ListServiceAccountsResponse{
		ServiceAccounts: result,
		Total:           &count,
	}, nil
}

func (s *ServiceAccountService) DeleteServiceAccount(
	ctx context.Context,
	req *nokkuv1.DeleteServiceAccountRequest,
) (*nokkuv1.DeleteServiceAccountResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		result, err := q.DeleteServiceAccount(ctx, req.GetId())
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return err
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.DeleteServiceAccountResponse{}, nil
}
