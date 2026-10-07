package iam

// SCIM Groups are workspace teams. The SCIM id is the team id and members
// reference user ids.

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"uuid"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/jackc/pgx/v5"
	filter "github.com/scim2/filter-parser/v2"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

type scimGroupHandler struct {
	svc *Service
	ws  actor.Workspace
}

func (h scimGroupHandler) tx(ctx context.Context, id string, fn func(*db.Queries) error) error {
	if _, err := uuid.Parse(id); id != "" && err != nil {
		return scimerrors.ScimErrorResourceNotFound(id)
	}
	err := h.svc.conn.WithWorkspace(ctx, fn)
	if errors.Is(err, pgx.ErrNoRows) {
		return scimerrors.ScimErrorResourceNotFound(id)
	}
	if db.IsUniqueViolation(err) {
		// One displayName per workspace, per RFC 7643 and the unique index.
		return scimerrors.ScimErrorUniqueness
	}
	return err
}

func (h scimGroupHandler) Create(r *http.Request, attrs scim.ResourceAttributes) (scim.Resource, error) {
	name := scimAttrString(attrs["displayName"])
	if name == "" {
		return scim.Resource{}, scimerrors.ScimErrorBadRequest("displayName is required")
	}
	var res scim.Resource
	err := h.tx(r.Context(), "", func(q *db.Queries) error {
		team, err := q.CreateTeam(r.Context(), &db.CreateTeamParams{WorkspaceID: h.ws.ID, Name: name})
		if err != nil {
			return err
		}
		if err := addTeamMembers(r.Context(), q, h.ws.ID, team.ID, scimMemberRefs(attrs["members"])); err != nil {
			return err
		}
		res, err = groupResource(r.Context(), q, h.ws, team)
		return err
	})
	return res, err
}

func (h scimGroupHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	var res scim.Resource
	err := h.tx(r.Context(), id, func(q *db.Queries) error {
		team, err := q.GetTeam(r.Context(), id)
		if err != nil {
			return err
		}
		res, err = groupResource(r.Context(), q, h.ws, team)
		return err
	})
	return res, err
}

func (h scimGroupHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	var all []scim.Resource
	err := h.tx(r.Context(), "", func(q *db.Queries) error {
		rows, err := q.ListTeams(r.Context(), &db.ListTeamsParams{WorkspaceID: h.ws.ID})
		if err != nil {
			return err
		}
		for _, row := range rows {
			res, err := groupResource(r.Context(), q, h.ws, &row.Team)
			if err != nil {
				return err
			}
			all = append(all, res)
		}
		return nil
	})
	if err != nil {
		return scim.Page{}, err
	}
	return paginate(all, params), nil
}

func (h scimGroupHandler) Replace(r *http.Request, id string, attrs scim.ResourceAttributes) (scim.Resource, error) {
	ctx := r.Context()
	var res scim.Resource
	err := h.tx(ctx, id, func(q *db.Queries) error {
		team, err := q.GetTeam(ctx, id)
		if err != nil {
			return err
		}
		if name := scimAttrString(attrs["displayName"]); name != "" && name != team.Name {
			if team, err = q.UpdateTeam(ctx, &db.UpdateTeamParams{TeamID: id, Name: &name}); err != nil {
				return err
			}
		}
		// The PUT representation is authoritative for members.
		next := scimMemberRefs(attrs["members"])
		current, err := q.ListTeamMembers(ctx, id)
		if err != nil {
			return err
		}
		for _, m := range current {
			if !slices.Contains(next, m.User.ID) {
				if err := q.RemoveTeamMember(
					ctx,
					&db.RemoveTeamMemberParams{TeamID: id, UserID: m.User.ID},
				); err != nil {
					return err
				}
			}
		}
		if err := addTeamMembers(ctx, q, h.ws.ID, id, next); err != nil {
			return err
		}
		res, err = groupResource(ctx, q, h.ws, team)
		return err
	})
	return res, err
}

func (h scimGroupHandler) Delete(r *http.Request, id string) error {
	return h.tx(r.Context(), id, func(q *db.Queries) error {
		_, err := q.DeleteTeam(r.Context(), id)
		return err
	})
}

func (h scimGroupHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	ctx := r.Context()
	var res scim.Resource
	changed := false
	err := h.tx(ctx, id, func(q *db.Queries) error {
		team, err := q.GetTeam(ctx, id)
		if err != nil {
			return err
		}
		err = eachScimOp(operations, func(opName, attr string, expr filter.Expression, value any) error {
			switch attr {
			case "displayName":
				name := scimAttrString(value)
				if name == "" {
					return nil
				}
				changed = true
				team, err = q.UpdateTeam(ctx, &db.UpdateTeamParams{TeamID: id, Name: &name})
				return err
			case "members":
				changed = true
				ids := scimMemberRefs(value)
				if opName != "remove" {
					return addTeamMembers(ctx, q, h.ws.ID, id, ids)
				}
				if len(ids) == 0 {
					// Okta puts the id in the path filter: members[value eq "id"].
					ids = scimFilterValues(expr)
				}
				for _, uid := range ids {
					if err := q.RemoveTeamMember(ctx, &db.RemoveTeamMemberParams{TeamID: id, UserID: uid}); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil || !changed {
			return err
		}
		res, err = groupResource(ctx, q, h.ws, team)
		return err
	})
	return res, err
}

// addTeamMembers skips non-members, a group never widens the workspace.
func addTeamMembers(ctx context.Context, q *db.Queries, workspaceID, teamID string, userIDs []string) error {
	for _, uid := range userIDs {
		if _, err := q.GetUser(ctx, &db.GetUserParams{
			WorkspaceID: workspaceID,
			ID:          uid,
		}); errors.Is(err, pgx.ErrNoRows) {
			continue
		} else if err != nil {
			return err
		}
		if err := q.AddTeamMember(ctx, &db.AddTeamMemberParams{TeamID: teamID, UserID: uid}); err != nil {
			return err
		}
	}
	return nil
}

func groupResource(
	ctx context.Context,
	q *db.Queries,
	ws actor.Workspace,
	team *db.Team,
) (scim.Resource, error) {
	rows, err := q.ListTeamMembers(ctx, team.ID)
	if err != nil {
		return scim.Resource{}, err
	}
	members := make([]any, 0, len(rows))
	for _, m := range rows {
		members = append(members, map[string]any{
			"value":   m.User.ID,
			"display": m.User.Email,
			"$ref":    ws.BaseURL + scimMountPath + scimUserEndpoint + "/" + m.User.ID,
		})
	}
	attrs := scim.ResourceAttributes{"members": members, "displayName": team.Name}
	return scim.Resource{
		ID:         team.ID,
		Attributes: attrs,
		Meta:       scim.Meta{Created: &team.CreatedAt, LastModified: &team.UpdatedAt},
	}, nil
}

func scimFilterValues(expr filter.Expression) []string {
	ae, ok := expr.(*filter.AttributeExpression)
	if !ok {
		return nil
	}
	if s, ok := ae.CompareValue.(string); ok {
		return []string{s}
	}
	return nil
}
