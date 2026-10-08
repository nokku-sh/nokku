package api

import (
	"cmp"
	"context"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"
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

// CreateServiceAccount makes the identity alone. A token comes from
// CreateServiceAccountToken.
func (s *serviceAccountService) CreateServiceAccount(
	ctx context.Context,
	req *nokkuv1.CreateServiceAccountRequest,
) (*nokkuv1.CreateServiceAccountResponse, error) {
	role := cmp.Or(req.GetRole(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	if !db.CanAssign(callerRole(ctx), role) {
		return nil, newError(connect.CodePermissionDenied, "role cannot be granted by you")
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		saID, err := q.CreateServiceAccount(ctx, &db.CreateServiceAccountParams{
			Name:        req.GetName(),
			Description: req.Description,
			Tags:        req.GetTags(),
			Role:        role,
		})
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

// DeleteServiceAccount takes every token and grant of the account with it.
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

// CreateServiceAccountToken returns the secret once, only its hash is stored.
func (s *serviceAccountService) CreateServiceAccountToken(
	ctx context.Context,
	req *nokkuv1.CreateServiceAccountTokenRequest,
) (*nokkuv1.CreateServiceAccountTokenResponse, error) {
	expiry, err := tokenExpiry(req.GetExpiresAt())
	if err != nil {
		return nil, err
	}
	if err := checkCanManageServiceAccount(ctx, s.cfg.Conn.Tenant(), req.GetServiceAccountId()); err != nil {
		return nil, err
	}
	var ttl time.Duration
	if expiry != nil {
		ttl = time.Until(*expiry)
	}
	tok, secret, err := s.cfg.IAM.IssueToken(ctx, iam.TokenParams{
		SubjectID: req.GetServiceAccountId(),
		Kind:      actor.KindServiceAccount,
		Method:    iam.MethodToken,
		Label:     req.GetLabel(),
		TTL:       ttl,
	})
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, tok.ID)
	return &nokkuv1.CreateServiceAccountTokenResponse{
		Token:  tok.ToServiceAccountToken(),
		Secret: &secret,
	}, nil
}

func (s *serviceAccountService) ListServiceAccountTokens(
	ctx context.Context,
	req *nokkuv1.ListServiceAccountTokensRequest,
) (*nokkuv1.ListServiceAccountTokensResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListServiceAccountTokens(ctx, req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	return &nokkuv1.ListServiceAccountTokensResponse{Tokens: db.ServiceAccountTokensToProto(rows)}, nil
}

// RevokeServiceAccountToken ends one token. The account and its other tokens
// stay, so a new token can be rolled out before the old one goes.
func (s *serviceAccountService) RevokeServiceAccountToken(
	ctx context.Context,
	req *nokkuv1.RevokeServiceAccountTokenRequest,
) (*nokkuv1.RevokeServiceAccountTokenResponse, error) {
	q := s.cfg.Conn.Tenant()
	if err := checkCanManageServiceAccount(ctx, q, req.GetServiceAccountId()); err != nil {
		return nil, err
	}
	n, err := q.DeleteServiceAccountToken(ctx, &db.DeleteServiceAccountTokenParams{
		ID:               req.GetId(),
		ServiceAccountID: req.GetServiceAccountId(),
	})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errNotFound
	}
	return &nokkuv1.RevokeServiceAccountTokenResponse{}, nil
}

// tokenExpiry is nil for a token that never expires.
func tokenExpiry(ts *timestamppb.Timestamp) (*time.Time, error) {
	if ts == nil {
		return nil, nil
	}
	expiry := ts.AsTime()
	if expiry.Before(time.Now()) {
		return nil, newError(connect.CodeInvalidArgument, "expires_at must be in the future")
	}
	return &expiry, nil
}

// checkCanManageServiceAccount keeps an editor from touching an account
// with a role above what they could grant.
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
