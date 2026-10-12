package iam

// SCIM Users are the workspace's users: id is the user id, userName the email, externalId is on the row.

import (
	"context"
	"net/http"
	"uuid"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	scimfilter "github.com/elimity-com/scim/filter"
	"github.com/elimity-com/scim/optional"
	filter "github.com/scim2/filter-parser/v2"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type scimUserHandler struct {
	svc *Service
	ws  actor.Workspace
}

func (h scimUserHandler) Create(r *http.Request, attrs scim.ResourceAttributes) (scim.Resource, error) {
	email := normalizeEmail(scimAttrString(attrs["userName"]))
	if email == "" {
		return scim.Resource{}, scimerrors.ScimErrorBadRequest("userName must be an email address")
	}
	u, err := h.svc.scimProvisionUser(
		r.Context(),
		email,
		scimDisplayName(attrs["displayName"], attrs["name"]),
		scimAttrBool(attrs["active"], true),
		scimAttrString(attrs["externalId"]),
	)
	if err != nil {
		return scim.Resource{}, err
	}
	return h.Get(r, u.ID)
}

func (h scimUserHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	u, err := h.user(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	return userResource(u), nil
}

// GetAll turns the connectors' userName eq "..." lookups into an indexed query.
func (h scimUserHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	rows, err := h.svc.conn.Tenant().ListSCIMUsers(r.Context(), &db.ListSCIMUsersParams{
		Email: userNameFilter(params.FilterValidator),
	})
	if err != nil {
		return scim.Page{}, err
	}
	all := make([]scim.Resource, 0, len(rows))
	for _, row := range rows {
		all = append(all, userResource(row))
	}
	return paginate(all, params), nil
}

func (h scimUserHandler) Replace(r *http.Request, id string, attrs scim.ResourceAttributes) (scim.Resource, error) {
	u, err := h.user(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	if requested := normalizeEmail(scimAttrString(attrs["userName"])); requested != "" && requested != u.Email {
		// userName is the login email and SCIM never renames it.
		return scim.Resource{}, scimerrors.ScimErrorMutability
	}
	var name *string
	if n := scimDisplayName(attrs["displayName"], attrs["name"]); n != "" {
		name = &n
	}
	var active *bool
	if a, ok := attrs["active"].(bool); ok {
		active = &a
	}
	return h.apply(r.Context(), id, name, active, scimAttrString(attrs["externalId"]))
}

func (h scimUserHandler) Delete(r *http.Request, id string) error {
	u, err := h.user(r.Context(), id)
	if err != nil {
		return err
	}
	return h.svc.scimDeprovisionUser(r.Context(), u)
}

func (h scimUserHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	u, err := h.user(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	var name *string
	var active *bool
	externalID := ""
	changed := false
	err = eachScimOp(operations, func(opName, attr string, _ filter.Expression, value any) error {
		switch attr {
		case "active":
			// Remove resets to the attribute default (RFC 7644 3.5.2.2).
			active = new(opName != "remove" && scimAttrBool(value, true))
			changed = true
		case "displayName", "name":
			n := ""
			if opName != "remove" {
				n = scimDisplayName(value, value)
			}
			name = &n
			changed = true
		case "emails":
			if s := scimEmailValue(value); s != "" && normalizeEmail(s) != u.Email {
				return scimerrors.ScimErrorMutability
			}
		case "externalId":
			if opName != "remove" {
				externalID = scimAttrString(value)
				changed = true
			}
		}
		return nil
	})
	if err != nil {
		return scim.Resource{}, err
	}
	if !changed {
		// RFC 7644 3.5.2 wants no content for a no-op, which the library renders from an empty resource.
		return scim.Resource{}, nil
	}
	return h.apply(r.Context(), id, name, active, externalID)
}

// user answers 404 for anything the workspace does not hold.
func (h scimUserHandler) user(ctx context.Context, id string) (*db.User, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, scimerrors.ScimErrorResourceNotFound(id)
	}
	rows, err := h.svc.conn.Tenant().ListSCIMUsers(ctx, &db.ListSCIMUsersParams{UserID: &id})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, scimerrors.ScimErrorResourceNotFound(id)
	}
	return rows[0], nil
}

func (h scimUserHandler) apply(
	ctx context.Context,
	id string,
	name *string,
	active *bool,
	externalID string,
) (scim.Resource, error) {
	err := h.svc.conn.TenantTx(ctx, func(q *db.Queries) error {
		if active != nil && !*active {
			if err := keepOwner(ctx, q, id); err != nil {
				return err
			}
		}
		if name != nil {
			if _, err := q.UpdateUser(ctx, &db.UpdateUserParams{ID: id, Name: name}); err != nil {
				return err
			}
		}
		if active != nil {
			if _, err := setUserActive(ctx, q, id, *active); err != nil {
				return err
			}
		}
		return linkSCIM(ctx, q, id, externalID)
	})
	if err != nil {
		return scim.Resource{}, err
	}
	if active != nil && !*active {
		if _, err := h.svc.revokeSubject(ctx, id); err != nil {
			return scim.Resource{}, err
		}
	}
	u, err := h.user(ctx, id)
	if err != nil {
		return scim.Resource{}, err
	}
	return userResource(u), nil
}

func userNameFilter(v *scimfilter.Validator) *string {
	if v == nil {
		return nil
	}
	ae, ok := v.GetFilter().(*filter.AttributeExpression)
	if !ok || ae.Operator != filter.EQ || ae.AttributePath.AttributeName != "userName" {
		return nil
	}
	s, ok := ae.CompareValue.(string)
	if !ok {
		return nil
	}
	return new(normalizeEmail(s))
}

func userResource(u *db.User) scim.Resource {
	attrs := scim.ResourceAttributes{
		"userName": u.Email,
		"active":   u.Active,
		"emails":   []any{map[string]any{"value": u.Email, "type": "work", "primary": true}},
	}
	if u.Name != "" {
		attrs["displayName"] = u.Name
		attrs["name"] = map[string]any{"formatted": u.Name}
	}
	out := scim.Resource{
		ID:         u.ID,
		Attributes: attrs,
		Meta:       scim.Meta{Created: &u.CreatedAt, LastModified: &u.UpdatedAt},
	}
	if u.ScimExternalID != nil {
		out.ExternalID = optional.NewString(*u.ScimExternalID)
	}
	return out
}

func scimEmailValue(v any) string {
	switch emails := v.(type) {
	case []any:
		if len(emails) == 0 {
			return ""
		}
		if m, ok := emails[0].(map[string]any); ok {
			return scimAttrString(m["value"])
		}
		return scimAttrString(emails[0])
	case map[string]any:
		return scimAttrString(emails["value"])
	default:
		return scimAttrString(v)
	}
}

func paginate(all []scim.Resource, params scim.ListRequestParams) scim.Page {
	if params.FilterValidator != nil {
		matching := all[:0]
		for _, res := range all {
			if params.FilterValidator.PassesFilter(res.Attributes) == nil {
				matching = append(matching, res)
			}
		}
		all = matching
	}
	total := len(all)
	lo := min(max(params.StartIndex, 1)-1, total)
	hi := min(lo+max(params.Count, 0), total)
	return scim.Page{TotalResults: total, Resources: append([]scim.Resource{}, all[lo:hi]...)}
}
