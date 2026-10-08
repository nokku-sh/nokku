package api

import (
	"context"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
)

type principalService struct {
	cfg *config.Config
}

func (s *principalService) ListPrincipals(
	ctx context.Context,
	req *nokkuv1.ListPrincipalsRequest,
) (*nokkuv1.ListPrincipalsResponse, error) {
	principals, err := s.cfg.Conn.Tenant().ListPrincipals(ctx, &db.ListPrincipalsParams{
		TargetID: req.GetTargetId(),
		Query:    req.Query,
		Limit:    req.Limit,
		Offset:   req.Offset,
	})
	if err != nil {
		return nil, err
	}
	count := int32(0)
	if len(principals) > 0 {
		count = principals[0].TotalCount
	}

	return &nokkuv1.ListPrincipalsResponse{
		Principals: db.PrincipalsToProto(principals),
		Total:      &count,
	}, nil
}

func (s *principalService) AddSubjectsToPrincipal(
	ctx context.Context,
	req *nokkuv1.AddSubjectsToPrincipalRequest,
) (*nokkuv1.AddSubjectsToPrincipalResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		// A principal of another workspace does not exist here.
		if _, err := q.GetPrincipalWorkspace(ctx, req.GetId()); err != nil {
			return err
		}

		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return errInvalidInput
		}
		for _, subjectID := range req.GetSubjectIds() {
			if err := q.AddPrincipalGrant(ctx, &db.AddPrincipalGrantParams{
				PrincipalID: req.GetId(),
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

	return &nokkuv1.AddSubjectsToPrincipalResponse{}, nil
}

func (s *principalService) RemoveSubjectsFromPrincipal(
	ctx context.Context,
	req *nokkuv1.RemoveSubjectsFromPrincipalRequest,
) (*nokkuv1.RemoveSubjectsFromPrincipalResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return errInvalidInput
		}
		for _, subjectID := range req.GetSubjectIds() {
			if err := q.RemovePrincipalGrant(ctx, &db.RemovePrincipalGrantParams{
				PrincipalID: req.GetId(),
				SubjectKind: kind,
				SubjectID:   subjectID,
			}); err != nil {
				return err
			}
		}
		// Grant removal is the whole lockout. The next sync drops the subject,
		// so an already issued cert matches no account.
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.RemoveSubjectsFromPrincipalResponse{}, nil
}

func (s *principalService) RevokeAllAccess(
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

// AddPrincipal is for manual targets, which have no daemon to report
// accounts. An existing account is returned unchanged.
func (s *principalService) AddPrincipal(
	ctx context.Context,
	req *nokkuv1.AddPrincipalRequest,
) (*nokkuv1.AddPrincipalResponse, error) {
	principal, err := s.cfg.Conn.Tenant().CreatePrincipal(ctx, &db.CreatePrincipalParams{
		TargetID: req.GetTargetId(),
		Username: req.GetUsername(),
	})
	if err != nil {
		return nil, err
	}

	return &nokkuv1.AddPrincipalResponse{Principal: principal.ToProto()}, nil
}

func (s *principalService) RemovePrincipal(
	ctx context.Context,
	req *nokkuv1.RemovePrincipalRequest,
) (*nokkuv1.RemovePrincipalResponse, error) {
	if err := s.cfg.Conn.Tenant().DeletePrincipal(ctx, req.GetId()); err != nil {
		return nil, err
	}

	return &nokkuv1.RemovePrincipalResponse{}, nil
}

var subjectKinds = map[string]nokkuv1.SubjectKind{
	db.SubjectKindUser:           nokkuv1.SubjectKind_SUBJECT_KIND_USER,
	db.SubjectKindTeam:           nokkuv1.SubjectKind_SUBJECT_KIND_TEAM,
	db.SubjectKindServiceAccount: nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT,
}

func subjectKind(k nokkuv1.SubjectKind) (string, bool) {
	switch k {
	case nokkuv1.SubjectKind_SUBJECT_KIND_USER:
		return db.SubjectKindUser, true
	case nokkuv1.SubjectKind_SUBJECT_KIND_TEAM:
		return db.SubjectKindTeam, true
	case nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT:
		return db.SubjectKindServiceAccount, true
	case nokkuv1.SubjectKind_SUBJECT_KIND_UNSPECIFIED:
		return "", false
	default:
		return "", false
	}
}
