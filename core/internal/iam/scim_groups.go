package iam

// SCIM sees only the teams it made or took over, IdPs delete unknown groups.

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"uuid"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/optional"
	"github.com/jackc/pgx/v5"
	filter "github.com/scim2/filter-parser/v2"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// The team RPC names, so a SCIM change reads like the same change made by hand.
const (
	actionCreateTeam       = "CreateTeam"
	actionUpdateTeam       = "UpdateTeam"
	actionDeleteTeam       = "DeleteTeam"
	actionAddTeamMember    = "AddTeamMember"
	actionRemoveTeamMember = "RemoveTeamMember"
)

type scimGroupHandler struct {
	svc *Service
	ws  actor.Workspace
}

func (h scimGroupHandler) Create(r *http.Request, attrs scim.ResourceAttributes) (scim.Resource, error) {
	if err := h.svc.requirePlan(r.Context()); err != nil {
		return scim.Resource{}, err
	}
	name := scimAttrString(attrs["displayName"])
	if name == "" {
		return scim.Resource{}, scimerrors.ScimErrorBadRequest("displayName is required")
	}
	ctx := r.Context()
	var res scim.Resource
	var events []*audit.Event
	err := h.tx(ctx, "", func(q *db.Queries) error {
		// A hand-made team an admin opened is taken over, keeping its id and grants. Its
		// members are the group's from now on.
		team, err := q.GetTeamByName(ctx, name)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if team, err = q.CreateTeam(ctx, &db.CreateTeamParams{Name: name}); err != nil {
				return err
			}
			events = append(events, groupEvent(actionCreateTeam, name, map[string]any{}))
		case err != nil:
			return err
		case team.ScimManaged:
			// Another group holds it, the two would overwrite each other.
			return scimerrors.ScimErrorUniqueness
		case !team.ScimOpen:
			// The group would get the team's access by using its name. An admin has to say so first.
			return scimerrors.ScimError{
				ScimType: scimerrors.ScimTypeUniqueness,
				Status:   http.StatusConflict,
				Detail: "a team named " + strconv.Quote(name) + " exists in Nokku and is not open for the identity " +
					"provider. Open it in the team's settings, then push the group again.",
			}
		default:
			events = append(events, groupEvent(actionUpdateTeam, team.ID, map[string]any{"name": team.Name}))
		}
		before, err := teamMembers(ctx, q, team.ID)
		if err != nil {
			return err
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
		changes, err := memberEvents(ctx, q, team, before)
		if err != nil {
			return err
		}
		events = append(events, changes...)
		res, err = groupResource(ctx, q, h.ws, team)
		return err
	})
	if err == nil {
		h.log(ctx, events)
	}
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
	if err := h.svc.requirePlan(r.Context()); err != nil {
		return scim.Resource{}, err
	}
	ctx := r.Context()
	var res scim.Resource
	var events []*audit.Event
	err := h.tx(ctx, id, func(q *db.Queries) error {
		team, err := q.GetSCIMTeam(ctx, id)
		if err != nil {
			return err
		}
		before, err := teamMembers(ctx, q, id)
		if err != nil {
			return err
		}
		if name := scimAttrString(attrs["displayName"]); name != "" && name != team.Name {
			if team, err = q.UpdateTeam(ctx, &db.UpdateTeamParams{TeamID: id, Name: &name}); err != nil {
				return err
			}
			events = append(events, groupEvent(actionUpdateTeam, id, map[string]any{"name": team.Name}))
		}
		if team, err = linkTeamSCIM(ctx, q, team, scimAttrString(attrs["externalId"])); err != nil {
			return err
		}
		if err := setTeamMembers(ctx, q, id, scimMemberRefs(attrs["members"])); err != nil {
			return err
		}
		changes, err := memberEvents(ctx, q, team, before)
		if err != nil {
			return err
		}
		events = append(events, changes...)
		res, err = groupResource(ctx, q, h.ws, team)
		return err
	})
	if err == nil {
		h.log(ctx, events)
	}
	return res, err
}

func (h scimGroupHandler) Delete(r *http.Request, id string) error {
	if err := h.svc.requirePlan(r.Context()); err != nil {
		return err
	}
	var name string
	err := h.tx(r.Context(), id, func(q *db.Queries) (err error) {
		name, err = q.DeleteSCIMTeam(r.Context(), id)
		return err
	})
	if err == nil {
		h.log(r.Context(), []*audit.Event{groupEvent(actionDeleteTeam, id, map[string]any{"name": name})})
	}
	return err
}

func (h scimGroupHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	if err := h.svc.requirePlan(r.Context()); err != nil {
		return scim.Resource{}, err
	}
	ctx := r.Context()
	var res scim.Resource
	var events []*audit.Event
	changed := false
	err := h.tx(ctx, id, func(q *db.Queries) error {
		team, err := q.GetSCIMTeam(ctx, id)
		if err != nil {
			return err
		}
		before, err := teamMembers(ctx, q, id)
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
				if team, err = q.UpdateTeam(ctx, &db.UpdateTeamParams{TeamID: id, Name: &name}); err != nil {
					return err
				}
				events = append(events, groupEvent(actionUpdateTeam, id, map[string]any{"name": team.Name}))
				return nil
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
					return q.AddTeamMembers(ctx, &db.AddTeamMembersParams{TeamID: id, UserIds: ids})
				case value == nil && expr == nil:
					// A bare remove takes every value (RFC 7644 3.5.2.2).
					return setTeamMembers(ctx, q, id, nil)
				}
				if len(ids) == 0 {
					// Okta puts the id in the filter: members[value eq "id"].
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
		changes, err := memberEvents(ctx, q, team, before)
		if err != nil {
			return err
		}
		events = append(events, changes...)
		res, err = groupResource(ctx, q, h.ws, team)
		return err
	})
	if err == nil {
		h.log(ctx, events)
	}
	return res, err
}

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

func setTeamMembers(ctx context.Context, q *db.Queries, teamID string, userIDs []string) error {
	current, err := q.ListTeamMembers(ctx, teamID)
	if err != nil {
		return err
	}
	for _, m := range current {
		if i := slices.Index(userIDs, m.User.ID); i >= 0 {
			// Already in, or a full sync would look every one up again.
			userIDs = slices.Delete(userIDs, i, i+1)
			continue
		}
		if err := q.RemoveTeamMember(ctx, &db.RemoveTeamMemberParams{TeamID: teamID, UserID: m.User.ID}); err != nil {
			return err
		}
	}
	return q.AddTeamMembers(ctx, &db.AddTeamMembersParams{TeamID: teamID, UserIds: userIDs})
}

// teamMembers maps member ids to the names the audit log shows for them.
func teamMembers(ctx context.Context, q *db.Queries, teamID string) (map[string]string, error) {
	rows, err := q.ListTeamMembers(ctx, teamID)
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(rows))
	for _, m := range rows {
		names[m.User.ID] = cmp.Or(m.User.Name, m.User.Email)
	}
	return names, nil
}

// memberEvents compares with the members read at the start, so an id that
// changed nothing writes no row.
func memberEvents(ctx context.Context, q *db.Queries, team *db.Team, before map[string]string) ([]*audit.Event, error) {
	after, err := teamMembers(ctx, q, team.ID)
	if err != nil {
		return nil, err
	}
	var events []*audit.Event
	for _, id := range slices.Sorted(maps.Keys(after)) {
		if _, ok := before[id]; !ok {
			events = append(events, groupEvent(actionAddTeamMember, team.ID,
				map[string]any{"name": team.Name, "member": after[id]}))
		}
	}
	for _, id := range slices.Sorted(maps.Keys(before)) {
		if _, ok := after[id]; !ok {
			events = append(events, groupEvent(actionRemoveTeamMember, team.ID,
				map[string]any{"name": team.Name, "member": before[id]}))
		}
	}
	return events, nil
}

func groupEvent(action, target string, details map[string]any) *audit.Event {
	details["method"] = string(MethodSCIM)
	return &audit.Event{Action: action, Target: target, Details: details}
}

// log runs after the commit, so a change that rolled back writes no row.
func (h scimGroupHandler) log(ctx context.Context, events []*audit.Event) {
	if h.svc.audit == nil {
		return
	}
	for _, e := range events {
		h.svc.audit.Log(ctx, e)
	}
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
