package api

import (
	"context"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
)

type principalService struct {
	cfg *config.Config
}

func newPrincipalService(cfg *config.Config) *principalService {
	return &principalService{cfg: cfg}
}

func (s *principalService) ListPrincipals(
	ctx context.Context,
	req *nokkuv1.ListPrincipalsRequest,
) (*nokkuv1.ListPrincipalsResponse, error) {
	var principals []*db.ListPrincipalsRow
	count := int32(0)

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		principals, err = q.ListPrincipals(ctx, &db.ListPrincipalsParams{
			TargetID: req.GetTargetId(),
			Query:    req.Query,
			Limit:    req.Limit,
			Offset:   req.Offset,
		})
		return err
	}); err != nil {
		return nil, err
	}
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
	var workspaceID string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspaceID, err = q.GetPrincipalWorkspace(ctx, req.GetId())
		if err != nil {
			return err
		}

		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return errInvalidInput
		}
		for _, subjectID := range req.GetSubjectIds() {
			if err := q.AddPrincipalGrant(ctx, &db.AddPrincipalGrantParams{
				PrincipalID: req.GetId(),
				WorkspaceID: workspaceID,
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
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
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
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return errInvalidInput
		}
		return q.RevokeSubjectAccessInWorkspace(ctx, &db.RevokeSubjectAccessInWorkspaceParams{
			WorkspaceID: actor.WorkspaceIDFromContext(ctx),
			SubjectKind: kind,
			SubjectID:   req.GetSubjectId(),
		})
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
	var principal *db.Principal
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		principal, err = q.CreatePrincipal(ctx, &db.CreatePrincipalParams{
			WorkspaceID: actor.WorkspaceIDFromContext(ctx),
			TargetID:    req.GetTargetId(),
			Username:    req.GetUsername(),
		})
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.AddPrincipalResponse{Principal: principal.ToProto()}, nil
}

func (s *principalService) RemovePrincipal(
	ctx context.Context,
	req *nokkuv1.RemovePrincipalRequest,
) (*nokkuv1.RemovePrincipalResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeletePrincipal(ctx, req.GetId())
	}); err != nil {
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
