package api

import (
	"context"
	"log/slog"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
)

type TeamService struct {
	cfg *config.Config
}

func NewTeamService(cfg *config.Config) *TeamService {
	return &TeamService{cfg: cfg}
}

func (s *TeamService) GetTeam(
	ctx context.Context,
	req *nokkuv1.GetTeamRequest,
) (*nokkuv1.GetTeamResponse, error) {
	var result *db.Team
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetTeam(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, ErrNotFound
	}
	if result == nil {
		return nil, ErrNotFound
	}
	return &nokkuv1.GetTeamResponse{
		Team: result.ToProto(),
	}, nil
}

func (s *TeamService) CreateTeam(
	ctx context.Context,
	req *nokkuv1.CreateTeamRequest,
) (*nokkuv1.CreateTeamResponse, error) {
	if err := s.cfg.Entitlements.Check(
		ctx,
		req.GetWorkspaceId(),
		entitlement.ResourceTeams,
	); err != nil {
		return nil, err
	}

	var result *db.Team
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.CreateTeam(ctx, &db.CreateTeamParams{
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.GetName(),
			Description: req.Description,
			Tags:        req.GetTags(),
		})
		if err != nil {
			return err
		}
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return nil
	}); err != nil {
		slog.Error("failed to create team", "error", err)
		return nil, ErrInternal
	}

	return &nokkuv1.CreateTeamResponse{
		Team: result.ToProto(),
	}, nil
}

func (s *TeamService) UpdateTeam(
	ctx context.Context,
	req *nokkuv1.UpdateTeamRequest,
) (*nokkuv1.UpdateTeamResponse, error) {
	var result *db.Team
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.UpdateTeam(ctx, &db.UpdateTeamParams{
			TeamID:      req.GetId(),
			Name:        req.Name,
			Description: req.Description,
			Tags:        req.GetTags(),
		})
		if err != nil {
			return err
		}
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return nil
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.UpdateTeamResponse{
		Team: result.ToProto(),
	}, nil
}

func (s *TeamService) DeleteTeam(
	ctx context.Context,
	req *nokkuv1.DeleteTeamRequest,
) (*nokkuv1.DeleteTeamResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		team, err := q.DeleteTeam(ctx, req.GetId())
		if err != nil {
			return err
		}
		meta.SetAuditWorkspaceID(ctx, team.WorkspaceID)
		return nil
	}); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.DeleteTeamResponse{}, nil
}

func (s *TeamService) ListTeams(
	ctx context.Context,
	req *nokkuv1.ListTeamsRequest,
) (*nokkuv1.ListTeamsResponse, error) {
	var result []*nokkuv1.Team
	var count int32
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		var err error
		count, err = q.CountTeams(ctx, &db.CountTeamsParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			Tags:        req.GetTags(),
		})
		if err != nil {
			return err
		}
		teams, err := q.ListTeams(ctx, &db.ListTeamsParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			Tags:        req.GetTags(),
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		if err != nil {
			return err
		}

		result = db.TeamsToProto(teams)
		for i, team := range teams {
			members, err := q.ListTeamMembers(ctx, team.ID)
			if err != nil {
				return err
			}
			result[i].Members = db.TeamMembersToProto(members)
		}
		return nil
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.ListTeamsResponse{
		Teams: result,
		Total: &count,
	}, nil
}

func (s *TeamService) AddTeamMember(
	ctx context.Context,
	req *nokkuv1.AddTeamMemberRequest,
) (*nokkuv1.AddTeamMemberResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.AddTeamMember(ctx, &db.AddTeamMemberParams{
			TeamID: req.GetTeamId(),
			UserID: req.GetUserId(),
		})
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.AddTeamMemberResponse{}, nil
}

func (s *TeamService) RemoveTeamMember(
	ctx context.Context,
	req *nokkuv1.RemoveTeamMemberRequest,
) (*nokkuv1.RemoveTeamMemberResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.RemoveTeamMember(ctx, &db.RemoveTeamMemberParams{
			TeamID: req.GetTeamId(),
			UserID: req.GetUserId(),
		})
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.RemoveTeamMemberResponse{}, nil
}
