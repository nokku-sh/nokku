package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
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
		return nil, ErrInternal
	}
	return &nokkuv1.SetPrincipalsResponse{}, nil
}

func (s *PrincipalService) ListPrincipals(
	ctx context.Context,
	req *nokkuv1.ListPrincipalsRequest,
) (*nokkuv1.ListPrincipalsResponse, error) {
	var principals []*db.ListPrincipalsRow
	var count int32

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		count, err = q.CountTargetPrincipals(ctx, req.GetTargetId())
		if err != nil {
			return err
		}

		principals, err = q.ListPrincipals(ctx, &db.ListPrincipalsParams{
			TargetID: req.GetTargetId(),
			Query:    req.Query,
			Limit:    req.Limit,
			Offset:   req.Offset,
		})
		return err
	}); err != nil {
		return nil, ErrInternal
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
		meta.SetAuditWorkspaceID(ctx, workspaceID)

		switch req.GetType() {
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_USER:
			if err := q.AddUsersToPrincipal(ctx, &db.AddUsersToPrincipalParams{
				UserIds:     req.GetSubjectIds(),
				PrincipalID: req.GetId(),
				WorkspaceID: workspaceID,
			}); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_TEAM:
			if err := q.AddTeamsToPrincipal(ctx, &db.AddTeamsToPrincipalParams{
				TeamIds:     req.GetSubjectIds(),
				PrincipalID: req.GetId(),
				WorkspaceID: workspaceID,
			}); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT:
			if err := q.AddServiceAccountsToPrincipal(ctx, &db.AddServiceAccountsToPrincipalParams{
				ServiceAccountIds: req.GetSubjectIds(),
				PrincipalID:       req.GetId(),
				WorkspaceID:       workspaceID,
			}); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_UNSPECIFIED:
			return connect.NewError(
				connect.CodeInvalidArgument,
				errors.New("invalid principal type"),
			)
		default:
			return connect.NewError(
				connect.CodeInvalidArgument,
				errors.New("invalid principal type"),
			)
		}

		return nil
	}); err != nil {
		var cerr *connect.Error
		if errors.As(err, &cerr) {
			return nil, err
		}
		slog.Error("failed to add subjects to principal", "error", err)
		return nil, ErrInternal
	}

	go s.cfg.Pool.Broadcast(workspaceID, &nokkuv1.Notification{
		EventType: nokkuv1.Notification_EVENT_TYPE_PRINCIPALS.Enum(),
	})
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
		meta.SetAuditWorkspaceID(ctx, workspaceID)

		switch req.GetType() {
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_USER:
			if err := q.RemoveUsersFromPrincipal(ctx, &db.RemoveUsersFromPrincipalParams{
				UserIds:     req.GetSubjectIds(),
				PrincipalID: req.GetId(),
			}); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_TEAM:
			if err := q.RemoveTeamsFromPrincipal(ctx, &db.RemoveTeamsFromPrincipalParams{
				TeamIds:     req.GetSubjectIds(),
				PrincipalID: req.GetId(),
			}); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT:
			if err := q.RemoveServiceAccountsFromPrincipal(
				ctx,
				&db.RemoveServiceAccountsFromPrincipalParams{
					ServiceAccountIds: req.GetSubjectIds(),
					PrincipalID:       req.GetId(),
				},
			); err != nil {
				return err
			}
		case nokkuv1.PrincipalType_PRINCIPAL_TYPE_UNSPECIFIED:
			return connect.NewError(
				connect.CodeInvalidArgument,
				errors.New("invalid principal type"),
			)
		default:
			return connect.NewError(
				connect.CodeInvalidArgument,
				errors.New("invalid principal type"),
			)
		}

		return nil
	}); err != nil {
		var cerr *connect.Error
		if errors.As(err, &cerr) {
			return nil, err
		}
		slog.Error("failed to remove subjects from principal", "error", err)
		return nil, ErrInternal
	}

	go s.cfg.Pool.Broadcast(workspaceID, &nokkuv1.Notification{
		EventType: nokkuv1.Notification_EVENT_TYPE_PRINCIPALS.Enum(),
	})
	return &nokkuv1.RemoveSubjectsFromPrincipalResponse{}, nil
}

func (s *PrincipalService) RevokeAllAccess(
	ctx context.Context,
	req *nokkuv1.RevokeAllAccessRequest,
) (*nokkuv1.RevokeAllAccessResponse, error) {
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

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
			return connect.NewError(
				connect.CodeInvalidArgument,
				errors.New("invalid subject type"),
			)
		default:
			return connect.NewError(
				connect.CodeInvalidArgument,
				errors.New("invalid subject type"),
			)
		}
		return nil
	}); err != nil {
		var cerr *connect.Error
		if errors.As(err, &cerr) {
			return nil, err
		}
		slog.Error("failed to revoke access", "error", err)
		return nil, ErrInternal
	}

	go s.cfg.Pool.Broadcast(req.GetWorkspaceId(), &nokkuv1.Notification{
		EventType: nokkuv1.Notification_EVENT_TYPE_PRINCIPALS.Enum(),
	})
	return &nokkuv1.RevokeAllAccessResponse{}, nil
}
