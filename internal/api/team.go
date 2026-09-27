package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
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
		return nil, DBError(err)
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
	var result *db.Team
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.CreateTeam(ctx, &db.CreateTeamParams{
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.GetName(),
			Description: req.Description,
			Tags:        req.GetTags(),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
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
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UpdateTeamResponse{
		Team: result.ToProto(),
	}, nil
}

func (s *TeamService) DeleteTeam(
	ctx context.Context,
	req *nokkuv1.DeleteTeamRequest,
) (*nokkuv1.DeleteTeamResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		_, err := q.DeleteTeam(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeleteTeamResponse{}, nil
}

func (s *TeamService) ListTeams(
	ctx context.Context,
	req *nokkuv1.ListTeamsRequest,
) (*nokkuv1.ListTeamsResponse, error) {
	var result []*nokkuv1.Team
	count := int32(0)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
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
		if len(teams) > 0 {
			count = teams[0].TotalCount
		}

		// Member counts in one grouped read; the members themselves are
		// fetched per team through ListTeamMembers when a view needs them.
		ids := make([]string, 0, len(teams))
		for _, t := range teams {
			ids = append(ids, t.Team.ID)
		}
		counts, err := q.CountTeamMembers(ctx, ids)
		if err != nil {
			return err
		}
		byTeam := make(map[string]int32, len(counts))
		for _, c := range counts {
			byTeam[c.TeamID] = c.MemberCount
		}

		result = db.TeamsToProto(teams)
		for _, t := range result {
			c := byTeam[t.GetId()]
			t.MemberCount = &c
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.ListTeamsResponse{
		Teams: result,
		Total: &count,
	}, nil
}

// ListTeamMembers returns one team's members with their identity display
// fields joined in. The dedicated read keeps ListTeams free of per-team
// member blobs; views load it when they actually show the members.
func (s *TeamService) ListTeamMembers(
	ctx context.Context,
	req *nokkuv1.ListTeamMembersRequest,
) (*nokkuv1.ListTeamMembersResponse, error) {
	var rows []*db.ListTeamMembersRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		rows, err = q.ListTeamMembers(ctx, req.GetTeamId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	members := make([]*nokkuv1.WorkspaceMember, 0, len(rows))
	for _, m := range rows {
		members = append(members, &nokkuv1.WorkspaceMember{
			Id:            &m.UserID,
			WorkspaceId:   &m.WorkspaceID,
			Name:          &m.Name,
			Email:         &m.Email,
			EmailVerified: &m.EmailVerified,
			Picture:       m.Picture,
			CreatedAt:     db.SafeTimestamp(&m.CreatedAt),
		})
	}
	return &nokkuv1.ListTeamMembersResponse{Members: members}, nil
}

// ListTeamsForUser returns the teams one user belongs to in a workspace. The
// user-profile modal used to derive this by scanning every team's members.
func (s *TeamService) ListTeamsForUser(
	ctx context.Context,
	req *nokkuv1.ListTeamsForUserRequest,
) (*nokkuv1.ListTeamsForUserResponse, error) {
	var teams []*db.Team
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		teams, err = q.ListTeamsForUser(ctx, &db.ListTeamsForUserParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	out := make([]*nokkuv1.Team, 0, len(teams))
	for _, t := range teams {
		out = append(out, t.ToProto())
	}
	return &nokkuv1.ListTeamsForUserResponse{Teams: out}, nil
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
		return nil, DBError(err)
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
		return nil, DBError(err)
	}

	return &nokkuv1.RemoveTeamMemberResponse{}, nil
}
