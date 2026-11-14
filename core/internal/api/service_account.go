package api

import (
	"cmp"
	"context"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

// Past any real use. Every public exchange loads the account's rules.
const (
	maxRulesPerAccount = 32
	// maxKeyLife is a year and a day, so the web app's one year preset fits in any time zone.
	maxKeyLife = 366 * 24 * time.Hour
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

// CreateServiceAccount makes no token, see CreateServiceAccountToken.
func (s *serviceAccountService) CreateServiceAccount(
	ctx context.Context,
	req *nokkuv1.CreateServiceAccountRequest,
) (*nokkuv1.CreateServiceAccountResponse, error) {
	role := cmp.Or(req.GetRole(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	if !db.CanAssign(callerRole(ctx), role) {
		return nil, connect.NewError(connect.CodePermissionDenied, "role cannot be granted by you")
	}
	source, err := ssh.SourceAddresses(req.GetSourceAddress())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err.Error())
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		saID, err := q.CreateServiceAccount(ctx, &db.CreateServiceAccountParams{
			Name:          req.GetName(),
			Description:   req.Description,
			Tags:          req.GetTags(),
			Role:          role,
			ForceCommand:  strings.TrimSpace(req.GetForceCommand()),
			SourceAddress: source,
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
	named, err := applyMask(req, req.GetUpdateMask())
	if err != nil {
		return nil, err
	}
	// No role keeps the one it has.
	role := req.GetRole()
	if role != nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED && !db.CanAssign(callerRole(ctx), role) {
		return nil, connect.NewError(connect.CodePermissionDenied, "role cannot be granted by you")
	}
	params := &db.UpdateServiceAccountParams{
		ServiceAccountID: req.GetId(),
		Name:             req.Name,
		Description:      req.Description,
		Role:             role,
		Tags:             maskedList(named("tags"), req.GetTags()),
	}
	// Unset keeps what the account has, empty takes the limit away.
	if req.ForceCommand != nil {
		params.ForceCommand = new(strings.TrimSpace(req.GetForceCommand()))
	}
	if req.SourceAddress != nil {
		list, err := ssh.SourceAddresses(req.GetSourceAddress())
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err.Error())
		}
		params.SourceAddress = &list
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if err := checkCanManageServiceAccount(ctx, q, req.GetId()); err != nil {
			return err
		}
		updatedID, err := q.UpdateServiceAccount(ctx, params)
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
	q := s.cfg.Conn.Tenant()
	params := &db.ListServiceAccountsParams{
		Query:  req.Query,
		Tags:   req.GetTags(),
		Role:   req.GetRole(),
		Limit:  req.Limit,
		Offset: req.Offset,
	}
	result, err := q.ListServiceAccounts(ctx, params)
	if err != nil {
		return nil, err
	}
	counted := result
	if len(result) == 0 && req.GetOffset() > 0 {
		// A page past the end has no row to carry the total, the first row does.
		params.Limit, params.Offset = new(int32(1)), nil
		if counted, err = q.ListServiceAccounts(ctx, params); err != nil {
			return nil, err
		}
	}
	var count int32
	if len(counted) > 0 {
		count = counted[0].TotalCount
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
	ttl, err := keyTTL(req.GetExpiresAt())
	if err != nil {
		return nil, err
	}
	if err := checkCanManageServiceAccount(ctx, s.cfg.Conn.Tenant(), req.GetServiceAccountId()); err != nil {
		return nil, err
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

// RevokeServiceAccountToken ends one token, so keys can rotate without a gap.
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
		// The session of a CI job, its row stays to keep the job token spent.
		n, err = q.RevokeWorkloadToken(ctx, &db.RevokeWorkloadTokenParams{
			ID:               req.GetId(),
			ServiceAccountID: req.GetServiceAccountId(),
		})
		if err != nil {
			return nil, err
		}
	}
	if n == 0 {
		return nil, errNotFound
	}
	return &nokkuv1.RevokeServiceAccountTokenResponse{}, nil
}

// AddServiceAccountFederation lets a rule's jobs sign in with no key to store.
func (s *serviceAccountService) AddServiceAccountFederation(
	ctx context.Context,
	req *nokkuv1.AddServiceAccountFederationRequest,
) (*nokkuv1.AddServiceAccountFederationResponse, error) {
	if err := iam.ValidateFederation(req.GetIssuer(), req.GetClaims()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err.Error())
	}
	q := s.cfg.Conn.Tenant()
	if err := checkCanManageServiceAccount(ctx, q, req.GetServiceAccountId()); err != nil {
		return nil, err
	}
	rules, err := q.ListServiceAccountFederations(ctx, req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	if len(rules) >= maxRulesPerAccount {
		return nil, connect.NewError(
			connect.CodeResourceExhausted,
			"this account has all the rules it can take, remove one first",
		)
	}
	rule, err := q.CreateServiceAccountFederation(ctx, &db.CreateServiceAccountFederationParams{
		ServiceAccountID: req.GetServiceAccountId(),
		Issuer:           req.GetIssuer(),
		Claims:           req.GetClaims(),
	})
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, rule.ID)
	audit.Set(ctx, "issuer", rule.Issuer)
	audit.Set(ctx, "claims", rule.Claims)
	return &nokkuv1.AddServiceAccountFederationResponse{Federation: rule.ToProto()}, nil
}

func (s *serviceAccountService) ListServiceAccountFederations(
	ctx context.Context,
	req *nokkuv1.ListServiceAccountFederationsRequest,
) (*nokkuv1.ListServiceAccountFederationsResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListServiceAccountFederations(ctx, req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	return &nokkuv1.ListServiceAccountFederationsResponse{Federations: db.ServiceAccountFederationsToProto(rows)}, nil
}

// RemoveServiceAccountFederation leaves a job's session to its own expiry.
func (s *serviceAccountService) RemoveServiceAccountFederation(
	ctx context.Context,
	req *nokkuv1.RemoveServiceAccountFederationRequest,
) (*nokkuv1.RemoveServiceAccountFederationResponse, error) {
	q := s.cfg.Conn.Tenant()
	if err := checkCanManageServiceAccount(ctx, q, req.GetServiceAccountId()); err != nil {
		return nil, err
	}
	n, err := q.DeleteServiceAccountFederation(ctx, &db.DeleteServiceAccountFederationParams{
		ID:               req.GetId(),
		ServiceAccountID: req.GetServiceAccountId(),
	})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errNotFound
	}
	return &nokkuv1.RemoveServiceAccountFederationResponse{}, nil
}

func keyTTL(ts *timestamppb.Timestamp) (time.Duration, error) {
	if ts == nil {
		return 0, connect.NewError(connect.CodeInvalidArgument, "a key needs an end date, set expires_at")
	}
	ttl := time.Until(ts.AsTime())
	if ttl <= 0 {
		return 0, connect.NewError(connect.CodeInvalidArgument, "expires_at must be in the future")
	}
	// A key is a bearer token with no binding, it must roll over.
	if ttl > maxKeyLife {
		return 0, connect.NewError(
			connect.CodeInvalidArgument,
			"a key lives a year at most, pick an earlier expires_at",
		)
	}
	return ttl, nil
}

// An editor can't touch an account above what they could grant.
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
