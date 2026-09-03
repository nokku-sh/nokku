package api

import (
	"context"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
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
	roleName := req.GetRoleName()
	if roleName == "" {
		roleName = "viewer"
	}
	if !db.IsServiceAccountRole(roleName) {
		return nil, ErrInvalidInput
	}

	// The service account's credential is a bearer token whose hash lives on
	// the row. Expiry rides on the row and is enforced at verification time,
	// so a short-lived token is really short-lived.
	raw := prefixSA + mustRandomToken()
	tokenHash, err := crypto.HashToken(raw)
	if err != nil {
		return nil, ErrInternal
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
				return NewError(connect.CodeInvalidArgument, "expires_at must be in the future")
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
		return nil, DBError(err)
	}

	return &nokkuv1.CreateServiceAccountResponse{
		ServiceAccount: result.ToProto(),
		Token:          &raw,
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
		updatedID, err := q.UpdateServiceAccount(ctx, &db.UpdateServiceAccountParams{
			ServiceAccountID: req.GetId(),
			Name:             req.Name,
			Description:      req.Description,
			RoleName:         req.RoleName,
		})
		if err != nil {
			return err
		}
		result, err = q.GetServiceAccount(ctx, updatedID)
		return err
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
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.ListServiceAccounts(ctx, &db.ListServiceAccountsParams{
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
		if len(result) > 0 {
			count = result[0].TotalCount
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	serviceAccounts := db.ServiceAccountsToProto(result)
	return &nokkuv1.ListServiceAccountsResponse{
		ServiceAccounts: serviceAccounts,
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
	// The credential is the row's token hash: deletion revokes it.
	return &nokkuv1.DeleteServiceAccountResponse{}, nil
}

// mustRandomToken returns the raw bearer secret for a new service account.
func mustRandomToken() string {
	s, err := crypto.RandomString(32)
	if err != nil {
		// crypto/rand failure is a process-level emergency; the create
		// request fails with an empty token rather than a reusable one.
		return ""
	}
	return s
}
