package iam

// SCIM Users are the workspace's users: id is the user id, userName the email, externalId is on the row.
// Inbound, the primary emails entry wins over userName. Authentik sends a plain username there.
// The IdP owns the address of the accounts it linked, so a changed one renames the login. Never the owner's.

import (
	"context"
	"maps"
	"net/http"
	"strings"
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
	email := scimEmail(attrs)
	if email == "" {
		return scim.Resource{}, scimerrors.ScimErrorBadRequest("emails or userName must hold an email address")
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
	var name *string
	if n := scimDisplayName(attrs["displayName"], attrs["name"]); n != "" {
		name = &n
	}
	var active *bool
	if a, ok := attrs["active"].(bool); ok {
		active = &a
	}
	return h.apply(r.Context(), u, scimEmail(attrs), name, active, scimAttrString(attrs["externalId"]))
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
	email, externalID := "", ""
	changed := false
	// Entra sends the name one part per operation.
	nameParts := map[string]any{}
	err = eachScimOp(operations, func(opName, attr string, expr filter.Expression, value any) error {
		switch attr {
		case "emails":
			// userName is left out here. Where it is no address, the two would rename the login back and forth.
			if s := scimPatchedLogin(opName, expr, value); s != "" {
				email = s
				changed = true
			}
		case "active":
			// Remove resets to the attribute default (RFC 7644 3.5.2.2).
			active = new(opName != "remove" && scimAttrBool(value, true))
			changed = true
		case "displayName":
			name = new(scimAttrString(value))
			changed = true
		case "name":
			parts, _ := value.(map[string]any)
			maps.Copy(nameParts, parts)
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
	// One name is stored, so half of one changes nothing. displayName wins over the parts.
	whole := scimAttrString(nameParts["formatted"]) != "" ||
		(scimAttrString(nameParts["givenName"]) != "" && scimAttrString(nameParts["familyName"]) != "")
	if name == nil && whole {
		name = new(scimDisplayName(nil, nameParts))
		changed = true
	}
	if !changed {
		// RFC 7644 3.5.2 wants no content for a no-op, which the library renders from an empty resource.
		return scim.Resource{}, nil
	}
	return h.apply(r.Context(), u, email, name, active, externalID)
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

// apply takes "" for an email the request did not carry.
func (h scimUserHandler) apply(
	ctx context.Context,
	before *db.User,
	email string,
	name *string,
	active *bool,
	externalID string,
) (scim.Resource, error) {
	id := before.ID
	// An account the IdP never linked keeps its address, and the request that links it does not rename yet.
	rename := email != "" && email != before.Email && before.ScimExternalID != nil
	err := h.svc.conn.TenantTx(ctx, func(q *db.Queries) error {
		if rename || (active != nil && !*active) {
			if err := keepOwner(ctx, q, id); err != nil {
				return err
			}
		}
		// First, it locks the workspace row and every other path takes that before a user row.
		if active != nil {
			if _, err := h.svc.SetUserActive(ctx, q, id, *active); err != nil {
				return err
			}
		}
		if rename {
			if _, err := q.SetUserEmail(ctx, &db.SetUserEmailParams{ID: id, Email: email}); err != nil {
				return mapUserError(err)
			}
			// A link mailed to the old address must not outlive it.
			if err := q.DeleteAllUserTokens(ctx, &id); err != nil {
				return err
			}
		}
		if name != nil {
			if _, err := q.UpdateUser(ctx, &db.UpdateUserParams{ID: id, Name: name}); err != nil {
				return err
			}
		}
		return linkSCIM(ctx, q, id, externalID)
	})
	if err != nil {
		return scim.Resource{}, scimUserError(err)
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
	if u.Active != before.Active {
		h.svc.recordActive(ctx, u)
	}
	if rename {
		h.svc.record(ctx, event{
			Action: actionEmailChanged, Kind: actor.KindUser, Method: MethodSCIM, UserID: u.ID, Email: u.Email,
		})
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

func scimEmail(attrs scim.ResourceAttributes) string {
	for _, v := range []any{attrs["emails"], attrs["userName"]} {
		if email := normalizeEmail(scimEmailValue(v)); strings.Contains(email, "@") {
			return email
		}
	}
	return ""
}

// scimPatchedLogin picks the login address out of a PATCH on emails, "" for a removal or a second address.
func scimPatchedLogin(opName string, expr filter.Expression, value any) string {
	if opName == "remove" {
		return ""
	}
	// A path filter names one entry. The one userResource reports is type eq "work" or primary eq true.
	byFilter := expr != nil
	if byFilter {
		ae, ok := expr.(*filter.AttributeExpression)
		if !ok || ae.Operator != filter.EQ {
			return ""
		}
		attr := ae.AttributePath.AttributeName
		if (!strings.EqualFold(attr, "type") || ae.CompareValue != "work") &&
			(!strings.EqualFold(attr, "primary") || ae.CompareValue != true) {
			return ""
		}
	}
	entries, ok := value.([]any)
	if !ok {
		entries = []any{value}
	}
	for _, e := range entries {
		m, _ := e.(map[string]any)
		if !byFilter && !scimAttrBool(m["primary"], false) && m["type"] != "work" {
			continue
		}
		if s := normalizeEmail(scimAttrString(m["value"])); strings.Contains(s, "@") {
			return s
		}
	}
	return ""
}

// scimEmailValue takes the primary entry of a list, or the first one when none is marked.
func scimEmailValue(v any) string {
	switch emails := v.(type) {
	case []any:
		first := ""
		for _, e := range emails {
			m, ok := e.(map[string]any)
			if !ok {
				m = map[string]any{"value": e}
			}
			s := scimAttrString(m["value"])
			if scimAttrBool(m["primary"], false) && s != "" {
				return s
			}
			if first == "" {
				first = s
			}
		}
		return first
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
