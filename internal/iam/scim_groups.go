package iam

// SCIM Group resource handler: maps /Groups onto workspace teams. The SCIM
// id is the team id and members reference user ids. Team queries run as
// nokku_system (no request principal exists), so every handler re-checks
// that the touched team belongs to the connector's workspace.

import (
	"context"
	"errors"
	"net/http"
	"slices"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/jackc/pgx/v5"
	filter "github.com/scim2/filter-parser/v2"

	"github.com/nokku-sh/nokku/internal/db"
)

type scimGroupHandler struct {
	svc         *Service
	workspaceID string
}

func (h scimGroupHandler) Create(r *http.Request, attrs scim.ResourceAttributes) (scim.Resource, error) {
	ctx := r.Context()
	name := scimAttrString(attrs["displayName"])
	if name == "" {
		return scim.Resource{}, scimerrors.ScimErrorBadRequest("displayName is required")
	}
	team, err := h.svc.q.CreateTeam(ctx, &db.CreateTeamParams{
		WorkspaceID: h.workspaceID,
		Name:        name,
	})
	if err != nil {
		if isUniqueViolation(err) {
			// One displayName per workspace, per RFC 7643 and the schema's
			// unique index.
			return scim.Resource{}, scimerrors.ScimErrorUniqueness
		}
		return scim.Resource{}, err
	}
	members := scimMemberRefs(attrs["members"])
	if err := h.addMembers(ctx, team.ID, members); err != nil {
		return scim.Resource{}, err
	}
	return h.resource(ctx, team.ID)
}

func (h scimGroupHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	return h.resource(r.Context(), id)
}

func (h scimGroupHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	ctx := r.Context()
	rows, err := h.svc.q.ListTeams(ctx, &db.ListTeamsParams{WorkspaceID: h.workspaceID})
	if err != nil {
		return scim.Page{}, err
	}

	all := make([]scim.Resource, 0, len(rows))
	for _, row := range rows {
		res, err := h.groupResource(ctx, &db.Team{
			ID:        row.ID,
			Name:      row.Name,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		})
		if err != nil {
			return scim.Page{}, err
		}
		if params.FilterValidator != nil && params.FilterValidator.PassesFilter(res.Attributes) != nil {
			continue
		}
		all = append(all, res)
	}
	return paginate(all, params), nil
}

func (h scimGroupHandler) Replace(r *http.Request, id string, attrs scim.ResourceAttributes) (scim.Resource, error) {
	ctx := r.Context()
	team, err := h.team(ctx, id)
	if err != nil {
		return scim.Resource{}, err
	}
	if name := scimAttrString(attrs["displayName"]); name != "" && name != team.Name {
		if _, err := h.svc.q.UpdateTeam(ctx, &db.UpdateTeamParams{TeamID: id, Name: &name}); err != nil {
			if isUniqueViolation(err) {
				return scim.Resource{}, scimerrors.ScimErrorUniqueness
			}
			return scim.Resource{}, err
		}
	}
	// Full member sync: the PUT representation is authoritative.
	next := scimMemberRefs(attrs["members"])
	current, err := h.memberIDs(ctx, id)
	if err != nil {
		return scim.Resource{}, err
	}
	for _, uid := range current {
		if !slices.Contains(next, uid) {
			if err := h.removeMember(ctx, id, uid); err != nil {
				return scim.Resource{}, err
			}
		}
	}
	if err := h.addMembers(ctx, id, next); err != nil {
		return scim.Resource{}, err
	}
	return h.resource(ctx, id)
}

func (h scimGroupHandler) Delete(r *http.Request, id string) error {
	if _, err := h.team(r.Context(), id); err != nil {
		return err
	}
	_, err := h.svc.q.DeleteTeam(r.Context(), id)
	return err
}

func (h scimGroupHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	ctx := r.Context()
	if _, err := h.team(ctx, id); err != nil {
		return scim.Resource{}, err
	}
	changed := false

	apply := func(opName, attr, _ string, expr filter.Expression, value any) error {
		switch attr {
		case "displayName":
			if name := scimAttrString(value); name != "" {
				if _, err := h.svc.q.UpdateTeam(ctx, &db.UpdateTeamParams{TeamID: id, Name: &name}); err != nil {
					if isUniqueViolation(err) {
						return scimerrors.ScimErrorUniqueness
					}
					return err
				}
				changed = true
			}
		case "members":
			ids := scimMemberRefs(value)
			if opName == "remove" && len(ids) == 0 {
				// "members[value eq \"x\"]" carries no Value: the ids live
				// in the path's filter expression (Okta's member removal).
				ids = scimFilterValues(expr)
			}
			switch opName {
			case "remove":
				for _, uid := range ids {
					if err := h.removeMember(ctx, id, uid); err != nil {
						return err
					}
				}
			default:
				if err := h.addMembers(ctx, id, ids); err != nil {
					return err
				}
			}
			changed = true
		}
		return nil
	}

	for _, op := range operations {
		if op.Path == nil {
			m, ok := op.Value.(map[string]any)
			if !ok {
				return scim.Resource{}, scimerrors.ScimErrorBadRequest("missing attribute path")
			}
			for attr, value := range m {
				if err := apply(op.Op, attr, "", nil, value); err != nil {
					return scim.Resource{}, err
				}
			}
			continue
		}
		attr := op.Path.AttributePath.AttributeName
		sub := op.Path.AttributePath.SubAttributeName()
		if sub == "" && op.Path.SubAttribute != nil {
			sub = *op.Path.SubAttribute
		}
		if err := apply(op.Op, attr, sub, op.Path.ValueExpression, op.Value); err != nil {
			return scim.Resource{}, err
		}
	}

	if !changed {
		return scim.Resource{}, nil
	}
	return h.resource(ctx, id)
}

// scimFilterValues extracts compared string values from a filter
// expression: the shape "members[value eq \"id\"]" resolves to.
func scimFilterValues(expr filter.Expression) []string {
	ae, ok := expr.(*filter.AttributeExpression)
	if !ok || ae.CompareValue == nil {
		return nil
	}
	if s, ok := ae.CompareValue.(string); ok {
		return []string{s}
	}
	return nil
}

// team loads a team and enforces the connector's tenant binding.
func (h scimGroupHandler) team(ctx context.Context, id string) (*db.Team, error) {
	team, err := h.svc.q.GetTeam(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, scimerrors.ScimErrorResourceNotFound(id)
		}
		return nil, err
	}
	if team.WorkspaceID != h.workspaceID {
		return nil, scimerrors.ScimErrorResourceNotFound(id)
	}
	return team, nil
}

func (h scimGroupHandler) resource(ctx context.Context, id string) (scim.Resource, error) {
	team, err := h.team(ctx, id)
	if err != nil {
		return scim.Resource{}, err
	}
	return h.groupResource(ctx, team)
}

func (h scimGroupHandler) groupResource(ctx context.Context, team *db.Team) (scim.Resource, error) {
	rows, err := h.svc.q.ListTeamMembers(ctx, team.ID)
	if err != nil {
		return scim.Resource{}, err
	}
	members := make([]any, 0, len(rows))
	for _, m := range rows {
		members = append(members, map[string]any{
			"value":   m.UserID,
			"display": m.Email,
			"$ref":    scimRef(h.svc.baseURL, scimUserEndpoint, m.UserID),
		})
	}
	attrs := scim.ResourceAttributes{"members": members}
	if team.Name != "" {
		attrs["displayName"] = team.Name
	}
	return scim.Resource{
		ID:         team.ID,
		Attributes: attrs,
		Meta: scim.Meta{
			Created:      &team.CreatedAt,
			LastModified: &team.UpdatedAt,
		},
	}, nil
}

// addMembers joins users into the team. A member id the workspace has
// never seen but that exists globally is a sync-ordering race (IdPs can
// push a group before its users): the org is asserting the person belongs,
// so they join the workspace with the team. Unknown ids are skipped: there
// is no userName to provision from, and the FK must not widen access.
func (h scimGroupHandler) addMembers(ctx context.Context, teamID string, userIDs []string) error {
	for _, uid := range userIDs {
		if _, err := h.svc.q.GetWorkspaceMember(ctx, &db.GetWorkspaceMemberParams{
			WorkspaceID: h.workspaceID,
			UserID:      uid,
		}); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if _, uerr := h.svc.q.GetUser(ctx, uid); uerr != nil {
				if errors.Is(uerr, pgx.ErrNoRows) {
					continue
				}
				return uerr
			}
			if err := h.svc.conn.WithTx(ctx, func(q *db.Queries) error {
				return q.EnsureWorkspaceMember(ctx, &db.EnsureWorkspaceMemberParams{
					WorkspaceID: h.workspaceID,
					UserID:      uid,
				})
			}); err != nil {
				return err
			}
		}
		if err := h.svc.q.AddTeamMember(ctx, &db.AddTeamMemberParams{TeamID: teamID, UserID: uid}); err != nil {
			return err
		}
	}
	return nil
}

func (h scimGroupHandler) removeMember(ctx context.Context, teamID, userID string) error {
	return h.svc.q.RemoveTeamMember(ctx, &db.RemoveTeamMemberParams{TeamID: teamID, UserID: userID})
}

func (h scimGroupHandler) memberIDs(ctx context.Context, teamID string) ([]string, error) {
	rows, err := h.svc.q.ListTeamMembers(ctx, teamID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.UserID)
	}
	return out, nil
}
