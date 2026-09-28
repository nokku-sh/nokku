package iam

// SCIM Users are managed workspace members. The SCIM id is the user id,
// userName is the email, and externalId lives in the credentials table.

import (
	"context"
	"net/http"
	"uuid"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	scimfilter "github.com/elimity-com/scim/filter"
	"github.com/elimity-com/scim/optional"
	filter "github.com/scim2/filter-parser/v2"

	"github.com/nokku-sh/nokku/internal/db"
)

type scimUserHandler struct {
	svc         *Service
	workspaceID string
}

func (h scimUserHandler) Create(r *http.Request, attrs scim.ResourceAttributes) (scim.Resource, error) {
	email := normalizeEmail(scimAttrString(attrs["userName"]))
	if email == "" {
		return scim.Resource{}, scimerrors.ScimErrorBadRequest("userName must be an email address")
	}
	u, err := h.svc.scimProvisionUser(
		r.Context(),
		h.workspaceID,
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
	m, err := h.member(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	return userResource(m), nil
}

// GetAll turns the connectors' userName eq "..." lookups into an indexed query.
func (h scimUserHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	rows, err := h.svc.sys.ListManagedMembers(r.Context(), &db.ListManagedMembersParams{
		WorkspaceID: h.workspaceID,
		Email:       userNameFilter(params.FilterValidator),
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
	m, err := h.member(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	if requested := normalizeEmail(scimAttrString(attrs["userName"])); requested != "" && requested != m.Email {
		// userName is the login email and SCIM never renames it.
		return scim.Resource{}, scimerrors.ScimErrorMutability
	}
	patch := db.UpdateUserParams{ID: id}
	if name := scimDisplayName(attrs["displayName"], attrs["name"]); name != "" {
		patch.Name = &name
	}
	if active, ok := attrs["active"].(bool); ok {
		patch.Active = &active
	}
	return h.apply(r.Context(), patch, scimAttrString(attrs["externalId"]))
}

func (h scimUserHandler) Delete(r *http.Request, id string) error {
	m, err := h.member(r.Context(), id)
	if err != nil {
		return err
	}
	return h.svc.scimDeprovisionUser(r.Context(), h.workspaceID, userFromRow(m))
}

func (h scimUserHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	m, err := h.member(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	patch := db.UpdateUserParams{ID: id}
	externalID := ""
	changed := false
	err = eachScimOp(operations, func(opName, attr string, _ filter.Expression, value any) error {
		switch attr {
		case "active":
			// Remove resets to the attribute default (RFC 7644 3.5.2.2).
			patch.Active = new(opName != "remove" && scimAttrBool(value, true))
			changed = true
		case "displayName", "name":
			name := ""
			if opName != "remove" {
				name = scimDisplayName(value, value)
			}
			patch.Name = &name
			changed = true
		case "emails":
			if s := scimEmailValue(value); s != "" && normalizeEmail(s) != m.Email {
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
		// RFC 7644 3.5.2 wants no content for a no-op, which the library
		// renders from an empty resource.
		return scim.Resource{}, nil
	}
	return h.apply(r.Context(), patch, externalID)
}

// member answers 404 for anything unmanaged, which is what an IdP expects.
func (h scimUserHandler) member(ctx context.Context, id string) (*db.ListManagedMembersRow, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, scimerrors.ScimErrorResourceNotFound(id)
	}
	rows, err := h.svc.sys.ListManagedMembers(ctx, &db.ListManagedMembersParams{
		WorkspaceID: h.workspaceID,
		UserID:      &id,
	})
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
	patch db.UpdateUserParams,
	externalID string,
) (scim.Resource, error) {
	err := h.svc.conn.WithTx(ctx, func(q *db.Queries) error {
		if _, err := q.UpdateUser(ctx, &patch); err != nil {
			return err
		}
		return linkSCIMCredential(ctx, q, h.workspaceID, patch.ID, externalID)
	})
	if err != nil {
		return scim.Resource{}, err
	}
	if patch.Active != nil && !*patch.Active {
		if _, err := h.svc.RevokeSubject(ctx, patch.ID); err != nil {
			return scim.Resource{}, err
		}
	}
	m, err := h.member(ctx, patch.ID)
	if err != nil {
		return scim.Resource{}, err
	}
	return userResource(m), nil
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

func userFromRow(m *db.ListManagedMembersRow) *db.User {
	return &db.User{ID: m.ID, Email: m.Email, Name: m.Name, Active: m.Active}
}

func userResource(m *db.ListManagedMembersRow) scim.Resource {
	attrs := scim.ResourceAttributes{
		"userName": m.Email,
		"active":   m.Active,
		"emails":   []any{map[string]any{"value": m.Email, "type": "work", "primary": true}},
	}
	if m.Name != "" {
		attrs["displayName"] = m.Name
		attrs["name"] = map[string]any{"formatted": m.Name}
	}
	out := scim.Resource{
		ID:         m.ID,
		Attributes: attrs,
		Meta:       scim.Meta{Created: &m.CreatedAt, LastModified: &m.UpdatedAt},
	}
	if m.ExternalID != "" {
		out.ExternalID = optional.NewString(m.ExternalID)
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
