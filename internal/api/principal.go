package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type PrincipalService struct {
	cfg *config.Config
}

func NewPrincipalService(cfg *config.Config) *PrincipalService {
	return &PrincipalService{cfg: cfg}
}

func (s *PrincipalService) ListPrincipals(
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
		return nil, DBError(err)
	}
	if len(principals) > 0 {
		count = principals[0].TotalCount
	}

	return &nokkuv1.ListPrincipalsResponse{
		Principals: db.PrincipalsToProto(principals),
		Total:      &count,
	}, nil
}

func (s *PrincipalService) AddSubjectsToPrincipal(
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
			return ErrInvalidInput
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
		return nil, DBError(err)
	}

	return &nokkuv1.AddSubjectsToPrincipalResponse{}, nil
}

func (s *PrincipalService) RemoveSubjectsFromPrincipal(
	ctx context.Context,
	req *nokkuv1.RemoveSubjectsFromPrincipalRequest,
) (*nokkuv1.RemoveSubjectsFromPrincipalResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return ErrInvalidInput
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

		// Grant removal is the whole lockout. The next sync drops the
		// subject from the principals map, so a certificate already issued
		// matches no account.
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.RemoveSubjectsFromPrincipalResponse{}, nil
}

func (s *PrincipalService) RevokeAllAccess(
	ctx context.Context,
	req *nokkuv1.RevokeAllAccessRequest,
) (*nokkuv1.RevokeAllAccessResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		kind, ok := subjectKind(req.GetKind())
		if !ok {
			return ErrInvalidInput
		}
		if err := q.RevokeSubjectAccessInWorkspace(ctx, &db.RevokeSubjectAccessInWorkspaceParams{
			WorkspaceID: req.GetWorkspaceId(),
			SubjectKind: kind,
			SubjectID:   req.GetSubjectId(),
		}); err != nil {
			return err
		}

		// Grant removal is the whole lockout, same as above: the subject
		// vanishes from every synced principals map.
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.RevokeAllAccessResponse{}, nil
}

// AddPrincipal adds one local account to a target. Manual targets have no
// daemon to report accounts, so the operator adds them here. Idempotent: an
// existing account is returned unchanged.
func (s *PrincipalService) AddPrincipal(
	ctx context.Context,
	req *nokkuv1.AddPrincipalRequest,
) (*nokkuv1.AddPrincipalResponse, error) {
	var principal *db.Principal
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		principal, err = q.CreatePrincipal(ctx, &db.CreatePrincipalParams{
			WorkspaceID: req.GetWorkspaceId(),
			TargetID:    req.GetTargetId(),
			Username:    req.GetUsername(),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.AddPrincipalResponse{Principal: principal.ToProto()}, nil
}

// RemovePrincipal drops one local account. Its grants cascade, so this is the
// deliberate way to stop granting access to an account that no longer exists.
func (s *PrincipalService) RemovePrincipal(
	ctx context.Context,
	req *nokkuv1.RemovePrincipalRequest,
) (*nokkuv1.RemovePrincipalResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeletePrincipal(ctx, req.GetId())
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.RemovePrincipalResponse{}, nil
}

// subjectKind maps the wire subject kind to principal_grants.subject_kind.
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
