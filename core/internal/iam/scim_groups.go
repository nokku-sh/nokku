package iam

// SCIM Groups are workspace teams. The SCIM id is the team id, members reference user ids, externalId is on the row.
// SCIM only sees the teams it made or took over, an IdP that syncs deletes every group it does not know.

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"uuid"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/optional"
	"github.com/jackc/pgx/v5"
	filter "github.com/scim2/filter-parser/v2"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type scimGroupHandler struct {
	svc *Service
	ws  actor.Workspace
}

func (h scimGroupHandler) tx(ctx context.Context, id string, fn func(*db.Queries) error) error {
	if _, err := uuid.Parse(id); id != "" && err != nil {
		return scimerrors.ScimErrorResourceNotFound(id)
	}
	err := h.svc.conn.TenantTx(ctx, fn)
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
	ctx := r.Context()
	var res scim.Resource
	err := h.tx(ctx, "", func(q *db.Queries) error {
		// A team made by hand is taken over, it keeps its id and its grants. The members are the group's from now on.
		team, err := q.GetTeamByName(ctx, name)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if team, err = q.CreateTeam(ctx, &db.CreateTeamParams{Name: name}); err != nil {
				return err
			}
		case err != nil:
			return err
		case team.ScimManaged:
			// Another group of the provider holds it, adopting would let the two overwrite each other.
			return scimerrors.ScimErrorUniqueness
		}
		if team, err = q.AdoptTeamSCIM(ctx, team.ID); err != nil {
			return err
		}
		if team, err = linkTeamSCIM(ctx, q, team, scimAttrString(attrs["externalId"])); err != nil {
			return err
		}
		if err := setTeamMembers(ctx, q, team.ID, scimMemberRefs(attrs["members"])); err != nil {
			return err
		}
		res, err = groupResource(ctx, q, h.ws, team)
		return err
	})
	return res, err
}

func (h scimGroupHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	var res scim.Resource
	err := h.tx(r.Context(), id, func(q *db.Queries) error {
		team, err := q.GetSCIMTeam(r.Context(), id)
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
		teams, err := q.ListSCIMTeams(r.Context())
		if err != nil {
			return err
		}
		for _, team := range teams {
			res, err := groupResource(r.Context(), q, h.ws, team)
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
		team, err := q.GetSCIMTeam(ctx, id)
		if err != nil {
			return err
		}
		if name := scimAttrString(attrs["displayName"]); name != "" && name != team.Name {
			if team, err = q.UpdateTeam(ctx, &db.UpdateTeamParams{TeamID: id, Name: &name}); err != nil {
				return err
			}
		}
		if team, err = linkTeamSCIM(ctx, q, team, scimAttrString(attrs["externalId"])); err != nil {
			return err
		}
		// The PUT representation is authoritative for members.
		if err := setTeamMembers(ctx, q, id, scimMemberRefs(attrs["members"])); err != nil {
			return err
		}
		res, err = groupResource(ctx, q, h.ws, team)
		return err
	})
	return res, err
}

func (h scimGroupHandler) Delete(r *http.Request, id string) error {
	return h.tx(r.Context(), id, func(q *db.Queries) error {
		_, err := q.DeleteSCIMTeam(r.Context(), id)
		return err
	})
}

func (h scimGroupHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	ctx := r.Context()
	var res scim.Resource
	changed := false
	err := h.tx(ctx, id, func(q *db.Queries) error {
		team, err := q.GetSCIMTeam(ctx, id)
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
			case "externalId":
				changed = true
				team, err = linkTeamSCIM(ctx, q, team, scimAttrString(value))
				return err
			case "members":
				changed = true
				ids := scimMemberRefs(value)
				switch {
				case opName == "replace" && expr == nil:
					return setTeamMembers(ctx, q, id, ids)
				case opName != "remove":
					return addTeamMembers(ctx, q, id, ids)
				case value == nil && expr == nil:
					// A bare remove takes every value (RFC 7644 3.5.2.2).
					return setTeamMembers(ctx, q, id, nil)
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

// linkTeamSCIM stores the identity provider's id on the team, the way linkSCIM does on a user.
func linkTeamSCIM(ctx context.Context, q *db.Queries, team *db.Team, externalID string) (*db.Team, error) {
	if externalID == "" || (team.ScimExternalID != nil && *team.ScimExternalID == externalID) {
		return team, nil
	}
	team, err := q.SetTeamSCIMExternalID(ctx, &db.SetTeamSCIMExternalIDParams{ID: team.ID, ExternalID: &externalID})
	if db.IsUniqueViolation(err) {
		return nil, scimerrors.ScimErrorBadRequest("externalId is already linked to another group")
	}
	return team, err
}

// setTeamMembers makes userIDs the whole membership.
func setTeamMembers(ctx context.Context, q *db.Queries, teamID string, userIDs []string) error {
	current, err := q.ListTeamMembers(ctx, teamID)
	if err != nil {
		return err
	}
	for _, m := range current {
		if i := slices.Index(userIDs, m.User.ID); i >= 0 {
			// Already in, the full list of a sync would look every one of them up again.
			userIDs = slices.Delete(userIDs, i, i+1)
			continue
		}
		if err := q.RemoveTeamMember(ctx, &db.RemoveTeamMemberParams{TeamID: teamID, UserID: m.User.ID}); err != nil {
			return err
		}
	}
	return addTeamMembers(ctx, q, teamID, userIDs)
}

// addTeamMembers skips non-members, a group never widens the workspace.
func addTeamMembers(ctx context.Context, q *db.Queries, teamID string, userIDs []string) error {
	for _, uid := range userIDs {
		if _, err := q.GetUser(ctx, uid); errors.Is(err, pgx.ErrNoRows) {
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
	out := scim.Resource{
		ID:         team.ID,
		Attributes: attrs,
		Meta:       scim.Meta{Created: &team.CreatedAt, LastModified: &team.UpdatedAt},
	}
	if team.ScimExternalID != nil {
		out.ExternalID = optional.NewString(*team.ScimExternalID)
	}
	return out, nil
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
