package api

import (
	"cmp"
	"context"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

type serviceAccountService struct {
	cfg *config.Config
}

func (s *serviceAccountService) GetServiceAccount(
	ctx context.Context,
	req *nokkuv1.GetServiceAccountRequest,
) (*nokkuv1.GetServiceAccountResponse, error) {
	result, err := s.cfg.Conn.Tenant().GetServiceAccount(ctx, req.GetId())
	if err != nil {
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
	role := cmp.Or(req.GetRole(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	if !db.CanAssign(callerRole(ctx), role) {
		return nil, newError(connect.CodePermissionDenied, "role cannot be granted by you")
	}

	raw, tokenHash := iam.NewAPIKey()

	var result *db.ServiceAccount
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		params := &db.CreateServiceAccountParams{
			Name:        req.GetName(),
			Description: req.Description,
			Tags:        req.GetTags(),
			Role:        role,
			TokenHash:   &tokenHash,
		}
		params.TokenExpiresAt, err = tokenExpiry(req.GetTokenExpiresAt())
		if err != nil {
			return err
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
	// No role keeps the one it has.
	role := req.GetRole()
	if role != nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED && !db.CanAssign(callerRole(ctx), role) {
		return nil, newError(connect.CodePermissionDenied, "role cannot be granted by you")
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if err := checkCanManageServiceAccount(ctx, q, req.GetId()); err != nil {
			return err
		}
		updatedID, err := q.UpdateServiceAccount(ctx, &db.UpdateServiceAccountParams{
			ServiceAccountID: req.GetId(),
			Name:             req.Name,
			Description:      req.Description,
			Role:             role,
			// An update replaces the tags. The query keeps the old ones for nil.
			Tags: append([]string{}, req.GetTags()...),
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
	result, err := s.cfg.Conn.Tenant().ListServiceAccounts(ctx, &db.ListServiceAccountsParams{
		Query:  req.Query,
		Tags:   req.GetTags(),
		Role:   req.GetRole(),
		Limit:  req.Limit,
		Offset: req.Offset,
	})
	if err != nil {
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
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := checkCanManageServiceAccount(ctx, q, req.GetId()); err != nil {
			return err
		}
		return q.DeleteServiceAccount(ctx, req.GetId())
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteServiceAccountResponse{}, nil
}

// RotateServiceAccountToken keeps the account, its id and its grants. Only the
// token changes, so nothing that names the account has to be set up again.
func (s *serviceAccountService) RotateServiceAccountToken(
	ctx context.Context,
	req *nokkuv1.RotateServiceAccountTokenRequest,
) (*nokkuv1.RotateServiceAccountTokenResponse, error) {
	expiry, err := tokenExpiry(req.GetTokenExpiresAt())
	if err != nil {
		return nil, err
	}
	raw, tokenHash := iam.NewAPIKey()

	var result *db.ServiceAccount
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if err := checkCanManageServiceAccount(ctx, q, req.GetId()); err != nil {
			return err
		}
		result, err = q.RotateServiceAccountToken(ctx, &db.RotateServiceAccountTokenParams{
			ServiceAccountID: req.GetId(),
			TokenHash:        &tokenHash,
			TokenExpiresAt:   expiry,
		})
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.RotateServiceAccountTokenResponse{
		ServiceAccount: result.ToProto(),
		Token:          &raw,
	}, nil
}

// tokenExpiry is nil for a token that never expires.
func tokenExpiry(ts *timestamppb.Timestamp) (*time.Time, error) {
	if ts == nil {
		return nil, nil
	}
	expiry := ts.AsTime()
	if expiry.Before(time.Now()) {
		return nil, newError(connect.CodeInvalidArgument, "token_expires_at must be in the future")
	}
	return &expiry, nil
}

func checkCanManageServiceAccount(ctx context.Context, q *db.Queries, id string) error {
	sa, err := q.GetServiceAccount(ctx, id)
	if err != nil {
		return err
	}
	if !db.CanAssign(callerRole(ctx), sa.Role) {
		return db.ErrPermissionDenied
	}
	return nil
}
