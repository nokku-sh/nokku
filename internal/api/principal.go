package api

import (
	"context"
	"errors"

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

func (s *PrincipalService) SetPrincipals(
	ctx context.Context,
	req *nokkuv1.SetPrincipalsRequest,
) (*nokkuv1.SetPrincipalsResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.SyncPrincipals(ctx, &db.SyncPrincipalsParams{
			TargetID:  req.GetTargetId(),
			Usernames: req.GetUsernames(),
		})
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.SetPrincipalsResponse{}, nil
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
		Principals: db.ListPrincipalsToProto(principals),
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

		switch req.GetType() {
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_USER:
			for _, subjectID := range req.GetSubjectIds() {
				if err := q.AddUserToPrincipal(ctx, &db.AddUserToPrincipalParams{
					UserID:      subjectID,
					PrincipalID: req.GetId(),
					WorkspaceID: workspaceID,
				}); err != nil {
					return err
				}
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_TEAM:
			for _, subjectID := range req.GetSubjectIds() {
				if err := q.AddTeamToPrincipal(ctx, &db.AddTeamToPrincipalParams{
					TeamID:      subjectID,
					PrincipalID: req.GetId(),
					WorkspaceID: workspaceID,
				}); err != nil {
					return err
				}
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT:
			for _, subjectID := range req.GetSubjectIds() {
				if err := q.AddServiceAccountToPrincipal(
					ctx,
					&db.AddServiceAccountToPrincipalParams{
						ServiceAccountID: subjectID,
						PrincipalID:      req.GetId(),
						WorkspaceID:      workspaceID,
					},
				); err != nil {
					return err
				}
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_UNSPECIFIED:
			return errors.New("invalid principal type")
		default:
			return errors.New("invalid principal type")
		}

		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	s.cfg.Pool.NotifyChange(workspaceID)
	return &nokkuv1.AddSubjectsToPrincipalResponse{}, nil
}

func (s *PrincipalService) RemoveSubjectsFromPrincipal(
	ctx context.Context,
	req *nokkuv1.RemoveSubjectsFromPrincipalRequest,
) (*nokkuv1.RemoveSubjectsFromPrincipalResponse, error) {
	var workspaceID string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspaceID, err = q.GetPrincipalWorkspace(ctx, req.GetId())
		if err != nil {
			return err
		}

		switch req.GetType() {
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_USER:
			for _, subjectID := range req.GetSubjectIds() {
				if err := q.RemoveUserFromPrincipal(ctx, &db.RemoveUserFromPrincipalParams{
					UserID:      subjectID,
					PrincipalID: req.GetId(),
				}); err != nil {
					return err
				}
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_TEAM:
			for _, subjectID := range req.GetSubjectIds() {
				if err := q.RemoveTeamFromPrincipal(ctx, &db.RemoveTeamFromPrincipalParams{
					TeamID:      subjectID,
					PrincipalID: req.GetId(),
				}); err != nil {
					return err
				}
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT:
			for _, subjectID := range req.GetSubjectIds() {
				if err := q.RemoveServiceAccountFromPrincipal(
					ctx,
					&db.RemoveServiceAccountFromPrincipalParams{
						ServiceAccountID: subjectID,
						PrincipalID:      req.GetId(),
					},
				); err != nil {
					return err
				}
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_UNSPECIFIED:
			return errors.New("invalid principal type")
		default:
			return errors.New("invalid principal type")
		}

		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	s.cfg.Pool.NotifyChange(workspaceID)
	return &nokkuv1.RemoveSubjectsFromPrincipalResponse{}, nil
}

func (s *PrincipalService) RevokeAllAccess(
	ctx context.Context,
	req *nokkuv1.RevokeAllAccessRequest,
) (*nokkuv1.RevokeAllAccessResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		switch req.GetType() {
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_USER:
			if err := q.RevokeUserAccessInWorkspace(ctx, &db.RevokeUserAccessInWorkspaceParams{
				UserID:      req.GetSubjectId(),
				WorkspaceID: req.GetWorkspaceId(),
			}); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_TEAM:
			if err := q.RevokeTeamAccessInWorkspace(ctx, &db.RevokeTeamAccessInWorkspaceParams{
				TeamID:      req.GetSubjectId(),
				WorkspaceID: req.GetWorkspaceId(),
			}); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT:
			if err := q.RevokeServiceAccountAccessInWorkspace(
				ctx,
				&db.RevokeServiceAccountAccessInWorkspaceParams{
					ServiceAccountID: req.GetSubjectId(),
					WorkspaceID:      req.GetWorkspaceId(),
				},
			); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_UNSPECIFIED:
			return errors.New("invalid principal type")
		default:
			return errors.New("invalid principal type")
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	s.cfg.Pool.NotifyChange(req.GetWorkspaceId())
	return &nokkuv1.RevokeAllAccessResponse{}, nil
}
