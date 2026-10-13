package api

import (
	"context"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

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
		// An account of another workspace does not exist here.
		if _, err := q.GetTargetAccountWorkspace(ctx, req.GetId()); err != nil {
			return err
		}

		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return errInvalidInput
		}
		for _, subjectID := range req.GetSubjectIds() {
			if err := q.AddGrant(ctx, &db.AddGrantParams{
				AccountID:   req.GetId(),
				SubjectKind: kind,
				SubjectID:   subjectID,
			}); err != nil {
				return err
			}
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
		for _, subjectID := range req.GetSubjectIds() {
			if err := q.RemoveGrant(ctx, &db.RemoveGrantParams{
				AccountID:   req.GetId(),
				SubjectKind: kind,
				SubjectID:   subjectID,
			}); err != nil {
				return err
			}
		}
		// Grant removal is the whole lockout. The next sync drops the subject, so an issued cert matches no account.
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
	if err := s.cfg.Conn.Tenant().RevokeSubjectAccessInWorkspace(ctx, &db.RevokeSubjectAccessInWorkspaceParams{
		SubjectKind: kind,
		SubjectID:   req.GetSubjectId(),
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.RevokeAllAccessResponse{}, nil
}

// AddTargetAccount is for manual targets, which have no daemon to report accounts.
func (s *targetAccountService) AddTargetAccount(
	ctx context.Context,
	req *nokkuv1.AddTargetAccountRequest,
) (*nokkuv1.AddTargetAccountResponse, error) {
	account, err := s.cfg.Conn.Tenant().CreateTargetAccount(ctx, &db.CreateTargetAccountParams{
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
	if err := s.cfg.Conn.Tenant().DeleteTargetAccount(ctx, req.GetId()); err != nil {
		return nil, err
	}

	return &nokkuv1.RemoveTargetAccountResponse{}, nil
}

var subjectKinds = map[string]nokkuv1.SubjectKind{
	db.SubjectKindUser:           nokkuv1.SubjectKind_SUBJECT_KIND_USER,
	db.SubjectKindTeam:           nokkuv1.SubjectKind_SUBJECT_KIND_TEAM,
	db.SubjectKindServiceAccount: nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT,
}

func subjectKind(k nokkuv1.SubjectKind) (string, bool) {
	for name, kind := range subjectKinds {
		if kind == k {
			return name, true
		}
	}
	return "", false
}
