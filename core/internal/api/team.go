package api

import (
	"context"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type teamService struct {
	cfg *app.Config
}

func (s *teamService) GetTeam(
	ctx context.Context,
	req *nokkuv1.GetTeamRequest,
) (*nokkuv1.GetTeamResponse, error) {
	team, err := s.cfg.Conn.Tenant().GetTeam(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &nokkuv1.GetTeamResponse{Team: team.ToProto()}, nil
}

func (s *teamService) CreateTeam(
	ctx context.Context,
	req *nokkuv1.CreateTeamRequest,
) (*nokkuv1.CreateTeamResponse, error) {
	team, err := s.cfg.Conn.Tenant().CreateTeam(ctx, &db.CreateTeamParams{
		Name:        req.GetName(),
		Description: req.Description,
		Tags:        req.GetTags(),
	})
	if err != nil {
		return nil, err
	}
	return &nokkuv1.CreateTeamResponse{Team: team.ToProto()}, nil
}

func (s *teamService) UpdateTeam(
	ctx context.Context,
	req *nokkuv1.UpdateTeamRequest,
) (*nokkuv1.UpdateTeamResponse, error) {
	named, err := applyMask(req, req.GetUpdateMask())
	if err != nil {
		return nil, err
	}
	team, err := s.cfg.Conn.Tenant().UpdateTeam(ctx, &db.UpdateTeamParams{
		TeamID:      req.GetId(),
		Name:        req.Name,
		Description: req.Description,
		Tags:        maskedList(named("tags"), req.GetTags()),
		ScimOpen:    req.ScimOpen,
	})
	if err != nil {
		return nil, err
	}
	audit.Set(ctx, "name", team.Name)
	return &nokkuv1.UpdateTeamResponse{Team: team.ToProto()}, nil
}

func (s *teamService) DeleteTeam(
	ctx context.Context,
	req *nokkuv1.DeleteTeamRequest,
) (*nokkuv1.DeleteTeamResponse, error) {
	team, err := s.cfg.Conn.Tenant().DeleteTeam(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	audit.Set(ctx, "name", team.Name)
	return &nokkuv1.DeleteTeamResponse{}, nil
}

func (s *teamService) ListTeams(
	ctx context.Context,
	req *nokkuv1.ListTeamsRequest,
) (*nokkuv1.ListTeamsResponse, error) {
	var result []*nokkuv1.Team
	var count int32
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		params := &db.ListTeamsParams{
			Query:  req.Query,
			Tags:   req.GetTags(),
			Limit:  req.Limit,
			Offset: req.Offset,
		}
		teams, err := q.ListTeams(ctx, params)
		if err != nil {
			return err
		}
		counted := teams
		if len(teams) == 0 && req.GetOffset() > 0 {
			// A page past the end has no row to carry the total, the first row does.
			params.Limit, params.Offset = new(int32(1)), nil
			if counted, err = q.ListTeams(ctx, params); err != nil {
				return err
			}
		}
		if len(counted) > 0 {
			count = counted[0].TotalCount
		}

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
			t.MemberCount = new(byTeam[t.GetId()])
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.ListTeamsResponse{
		Teams: result,
		Total: &count,
	}, nil
}

func (s *teamService) ListTeamMembers(
	ctx context.Context,
	req *nokkuv1.ListTeamMembersRequest,
) (*nokkuv1.ListTeamMembersResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListTeamMembers(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	members := make([]*nokkuv1.User, 0, len(rows))
	for _, m := range rows {
		members = append(members, m.User.ToProto())
	}
	return &nokkuv1.ListTeamMembersResponse{Members: members}, nil
}

func (s *teamService) ListTeamsForUser(
	ctx context.Context,
	req *nokkuv1.ListTeamsForUserRequest,
) (*nokkuv1.ListTeamsForUserResponse, error) {
	teams, err := s.cfg.Conn.Tenant().ListTeamsForUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	out := make([]*nokkuv1.Team, 0, len(teams))
	for _, t := range teams {
		out = append(out, t.ToProto())
	}
	return &nokkuv1.ListTeamsForUserResponse{Teams: out}, nil
}

func (s *teamService) AddTeamMember(
	ctx context.Context,
	req *nokkuv1.AddTeamMemberRequest,
) (*nokkuv1.AddTeamMemberResponse, error) {
	q := s.cfg.Conn.Tenant()
	if err := auditMember(ctx, q, req.GetTeamId(), req.GetUserId()); err != nil {
		return nil, err
	}
	if err := q.AddTeamMember(ctx, &db.AddTeamMemberParams{
		TeamID: req.GetTeamId(),
		UserID: req.GetUserId(),
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.AddTeamMemberResponse{}, nil
}

func (s *teamService) RemoveTeamMember(
	ctx context.Context,
	req *nokkuv1.RemoveTeamMemberRequest,
) (*nokkuv1.RemoveTeamMemberResponse, error) {
	q := s.cfg.Conn.Tenant()
	if err := auditMember(ctx, q, req.GetTeamId(), req.GetUserId()); err != nil {
		return nil, err
	}
	if err := q.RemoveTeamMember(ctx, &db.RemoveTeamMemberParams{
		TeamID: req.GetTeamId(),
		UserID: req.GetUserId(),
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.RemoveTeamMemberResponse{}, nil
}

// auditMember names the team and the person of a membership change.
func auditMember(ctx context.Context, q *db.Queries, teamID, userID string) error {
	names, err := q.GetNames(ctx, []string{teamID, userID})
	if err != nil {
		return err
	}
	audit.Set(ctx, "name", names[0])
	audit.Set(ctx, "member", names[1])
	return nil
}
