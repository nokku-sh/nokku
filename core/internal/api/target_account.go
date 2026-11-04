package api

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

var subjectKinds = map[string]nokkuv1.SubjectKind{
	db.SubjectKindUser:           nokkuv1.SubjectKind_SUBJECT_KIND_USER,
	db.SubjectKindTeam:           nokkuv1.SubjectKind_SUBJECT_KIND_TEAM,
	db.SubjectKindServiceAccount: nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT,
}

type targetAccountService struct {
	cfg *config.Config
}

func (s *targetAccountService) ListTargetAccounts(
	ctx context.Context,
	req *nokkuv1.ListTargetAccountsRequest,
) (*nokkuv1.ListTargetAccountsResponse, error) {
	accounts, err := s.cfg.Conn.Tenant().ListTargetAccounts(ctx, &db.ListTargetAccountsParams{
		TargetID: req.GetTargetId(),
		Query:    req.Query,
		Limit:    req.Limit,
		Offset:   req.Offset,
	})
	if err != nil {
		return nil, err
	}
	count := int32(0)
	if len(accounts) > 0 {
		count = accounts[0].TotalCount
	}

	return &nokkuv1.ListTargetAccountsResponse{
		Accounts: db.TargetAccountsToProto(accounts),
		Total:    &count,
	}, nil
}

func (s *targetAccountService) AddSubjects(
	ctx context.Context,
	req *nokkuv1.AddSubjectsRequest,
) (*nokkuv1.AddSubjectsResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return errInvalidInput
		}
		// Also the check that the account is this workspace's.
		if err := auditGrant(ctx, q, req.GetId(), kind, req.GetSubjectIds()); err != nil {
			return err
		}
		var expiresAt *time.Time
		if req.GetExpiresAt() != nil {
			expiresAt = new(req.GetExpiresAt().AsTime())
		}
		for _, subjectID := range req.GetSubjectIds() {
			if err := q.PutGrant(ctx, &db.PutGrantParams{
				AccountID:   req.GetId(),
				SubjectKind: kind,
				SubjectID:   subjectID,
				ExpiresAt:   expiresAt,
			}); err != nil {
				return err
			}
		}
		if expiresAt != nil {
			audit.Set(ctx, "expires_at", *expiresAt)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.AddSubjectsResponse{}, nil
}

func (s *targetAccountService) RemoveSubjects(
	ctx context.Context,
	req *nokkuv1.RemoveSubjectsRequest,
) (*nokkuv1.RemoveSubjectsResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return errInvalidInput
		}
		// Removing from an account that is gone stays a no-op, it just has no names.
		if err := auditGrant(ctx, q, req.GetId(), kind, req.GetSubjectIds()); err != nil &&
			!errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		for _, subjectID := range req.GetSubjectIds() {
			if err := q.RemoveGrant(ctx, &db.RemoveGrantParams{
				AccountID:   req.GetId(),
				SubjectKind: kind,
				SubjectID:   subjectID,
			}); err != nil {
				return err
			}
		}
		// Grant removal is the whole lockout. The next sync drops the subject,
		// so an issued cert matches no account.
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.RemoveSubjectsResponse{}, nil
}

func (s *targetAccountService) RevokeAllAccess(
	ctx context.Context,
	req *nokkuv1.RevokeAllAccessRequest,
) (*nokkuv1.RevokeAllAccessResponse, error) {
	kind, ok := subjectKind(req.GetKind())
	if !ok {
		return nil, errInvalidInput
	}
	q := s.cfg.Conn.Tenant()
	audit.Set(ctx, "subject_kind", kind)
	if err := auditName(ctx, q, "name", req.GetSubjectId()); err != nil {
		return nil, err
	}
	if err := q.RevokeSubjectAccessInWorkspace(ctx, &db.RevokeSubjectAccessInWorkspaceParams{
		SubjectKind: kind,
		SubjectID:   req.GetSubjectId(),
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.RevokeAllAccessResponse{}, nil
}

// AddTargetAccount is for manual targets, no daemon reports their accounts.
func (s *targetAccountService) AddTargetAccount(
	ctx context.Context,
	req *nokkuv1.AddTargetAccountRequest,
) (*nokkuv1.AddTargetAccountResponse, error) {
	q := s.cfg.Conn.Tenant()
	audit.Set(ctx, "username", req.GetUsername())
	if err := auditName(ctx, q, "target", req.GetTargetId()); err != nil {
		return nil, err
	}
	account, err := q.CreateTargetAccount(ctx, &db.CreateTargetAccountParams{
		TargetID: req.GetTargetId(),
		Username: req.GetUsername(),
	})
	if err != nil {
		return nil, err
	}

	return &nokkuv1.AddTargetAccountResponse{Account: account.ToProto()}, nil
}

func (s *targetAccountService) RemoveTargetAccount(
	ctx context.Context,
	req *nokkuv1.RemoveTargetAccountRequest,
) (*nokkuv1.RemoveTargetAccountResponse, error) {
	q := s.cfg.Conn.Tenant()
	// Removing an account that is gone stays a no-op, it just has no names.
	if err := auditAccount(ctx, q, req.GetId()); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err := q.DeleteTargetAccount(ctx, req.GetId()); err != nil {
		return nil, err
	}

	return &nokkuv1.RemoveTargetAccountResponse{}, nil
}

// auditGrant names a grant change in its audit event: the server, the account and who, as they are called now.
func auditGrant(ctx context.Context, q *db.Queries, accountID, kind string, subjectIDs []string) error {
	if err := auditAccount(ctx, q, accountID); err != nil {
		return err
	}
	names, err := q.GetNames(ctx, subjectIDs)
	if err != nil {
		return err
	}
	audit.Set(ctx, "subject_kind", kind)
	audit.Set(ctx, "subjects", names)
	return nil
}

// auditAccount names a login account by its server and username.
func auditAccount(ctx context.Context, q *db.Queries, accountID string) error {
	acc, err := q.GetTargetAccountLabel(ctx, accountID)
	if err != nil {
		return err
	}
	audit.Set(ctx, "target", acc.TargetName)
	audit.Set(ctx, "username", acc.Username)
	return nil
}

func subjectKind(k nokkuv1.SubjectKind) (string, bool) {
	for name, kind := range subjectKinds {
		if kind == k {
			return name, true
		}
	}
	return "", false
}
