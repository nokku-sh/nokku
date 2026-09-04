package iam

// SCIM User resource handler: maps /Users onto workspace members. The SCIM
// id is the user id, userName is the email, and externalId rides the
// credentials table (type 'scim', provider = workspace id) so a
// SCIM-provisioned user and the SSO identity of the same person resolve to
// one account.

import (
	"context"
	"errors"
	"net/http"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/optional"
	"github.com/jackc/pgx/v5"

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
	name := scimDisplayName(attrs["displayName"], attrs["name"])
	u, err := h.svc.scimProvisionUser(
		r.Context(),
		h.workspaceID,
		email,
		name,
		scimAttrBool(attrs["active"], true),
		scimAttrString(attrs["externalId"]),
	)
	if err != nil {
		return scim.Resource{}, err
	}
	return h.resource(r.Context(), u)
}

func (h scimUserHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	u, err := h.member(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	return h.resource(r.Context(), u)
}

func (h scimUserHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	ctx := r.Context()
	rows, err := h.svc.q.ListWorkspaceMembers(ctx, &db.ListWorkspaceMembersParams{
		WorkspaceID: h.workspaceID,
	})
	if err != nil {
		return scim.Page{}, err
	}
	externals := h.externalIDs(ctx)

	all := make([]scim.Resource, 0, len(rows))
	for _, row := range rows {
		res := memberResource(row, externals[row.UserID])
		if params.FilterValidator != nil && params.FilterValidator.PassesFilter(res.Attributes) != nil {
			continue
		}
		all = append(all, res)
	}
	return paginate(all, params), nil
}

func (h scimUserHandler) Replace(r *http.Request, id string, attrs scim.ResourceAttributes) (scim.Resource, error) {
	ctx := r.Context()
	u, err := h.member(ctx, id)
	if err != nil {
		return scim.Resource{}, err
	}
	if requested := normalizeEmail(scimAttrString(attrs["userName"])); requested != "" && requested != u.Email {
		// userName is the login email; SCIM never renames it. An IdP-side
		// rename surfaces as invalidMutability instead of a silent drift
		// between the two systems.
		return scim.Resource{}, scimerrors.ScimErrorMutability
	}
	externalID := scimAttrString(attrs["externalId"])
	patch := scimUserPatch(attrs)
	u, err = h.apply(ctx, id, patch, externalID, externalID != "")
	if err != nil {
		return scim.Resource{}, err
	}
	if err := h.revokeOnDeactivate(ctx, patch, u); err != nil {
		return scim.Resource{}, err
	}
	return h.resource(ctx, u)
}

func (h scimUserHandler) Delete(r *http.Request, id string) error {
	if _, err := h.member(r.Context(), id); err != nil {
		return err
	}
	return h.svc.scimDeprovisionUser(r.Context(), h.workspaceID, id)
}

func (h scimUserHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	ctx := r.Context()
	u, err := h.member(ctx, id)
	if err != nil {
		return scim.Resource{}, err
	}

	patch := UpdateUserPatch{}
	externalID := ""
	externalSet := false
	changed := false

	apply := func(opName, attr, _ string, value any) error {
		switch attr {
		case "active":
			// Remove resets to the attribute default (RFC 7644 3.5.2.2).
			active := opName != "remove" && scimAttrBool(value, true)
			patch.Active = &active
			changed = true
		case "displayName", "name":
			name := ""
			if opName != "remove" {
				name = scimDisplayName(value, value)
			}
			patch.Name = &name
			changed = true
		case "emails":
			if s := scimEmailValue(value); s != "" && s != u.Email {
				// The login email never changes over SCIM; see Replace.
				return scimerrors.ScimErrorMutability
			}
		case "externalId":
			if opName == "remove" {
				return nil
			}
			externalID = scimAttrString(value)
			externalSet = true
			changed = true
		}
		return nil
	}

	for _, op := range operations {
		if op.Path == nil {
			// Path-less add/replace carries a full or partial attrs object.
			m, ok := op.Value.(map[string]any)
			if !ok {
				return scim.Resource{}, scimerrors.ScimErrorBadRequest("missing attribute path")
			}
			for attr, value := range m {
				if err := apply(op.Op, attr, "", value); err != nil {
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
		if err := apply(op.Op, attr, sub, op.Value); err != nil {
			return scim.Resource{}, err
		}
	}

	if !changed {
		// Nothing to persist: RFC 7644 3.5.2 wants a no-content answer for
		// idempotent no-ops, which the library renders from an empty
		// resource.
		return scim.Resource{}, nil
	}
	u, err = h.apply(ctx, id, patch, externalID, externalSet && externalID != "")
	if err != nil {
		return scim.Resource{}, err
	}
	if err := h.revokeOnDeactivate(ctx, patch, u); err != nil {
		return scim.Resource{}, err
	}
	return h.resource(ctx, u)
}

// revokeOnDeactivate drops the account's sessions when the connector
// deactivated it: the active check already fails every request closed, and
// the revocation keeps device listings from showing dead sessions.
func (h scimUserHandler) revokeOnDeactivate(
	ctx context.Context,
	patch UpdateUserPatch,
	u *db.User,
) error {
	if patch.Active == nil || *patch.Active || u.Active {
		return nil
	}
	_, err := h.svc.Sessions.RevokeSubject(ctx, u.ID)
	return err
}

// member loads the user and requires workspace membership: SCIM resources
// are scoped to the connector's workspace, and anything else is a 404, the
// same answer an IdP would give a nonexistent id.
func (h scimUserHandler) member(ctx context.Context, id string) (*db.User, error) {
	_, err := h.svc.q.GetWorkspaceMember(ctx, &db.GetWorkspaceMemberParams{
		WorkspaceID: h.workspaceID,
		UserID:      id,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, scimerrors.ScimErrorResourceNotFound(id)
		}
		return nil, err
	}
	u, err := h.svc.q.GetUser(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, scimerrors.ScimErrorResourceNotFound(id)
		}
		return nil, err
	}
	return u, nil
}

func (h scimUserHandler) resource(ctx context.Context, u *db.User) (scim.Resource, error) {
	var externalID string
	subject, err := h.svc.q.GetSCIMCredentialByUser(ctx, &db.GetSCIMCredentialByUserParams{
		UserID:      u.ID,
		WorkspaceID: h.workspaceID,
	})
	switch {
	case err == nil:
		externalID = subject
	case !errors.Is(err, pgx.ErrNoRows):
		return scim.Resource{}, err
	}
	return userResource(u, externalID), nil
}

// apply persists a user patch and, when the request carried an externalId,
// the identity link. The re-link is idempotent: the same subject on the
// same user is a no-op upsert.
func (h scimUserHandler) apply(
	ctx context.Context,
	id string,
	patch UpdateUserPatch,
	externalID string,
	linkExternal bool,
) (*db.User, error) {
	u, err := h.svc.UpdateUser(ctx, id, patch)
	if err != nil {
		return nil, err
	}
	if !linkExternal {
		return u, nil
	}
	err = h.svc.conn.WithTx(ctx, func(q *db.Queries) error {
		return linkSCIMCredential(ctx, q, h.workspaceID, id, externalID)
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// externalIDs maps user id to SCIM externalId in one read for list pages.
func (h scimUserHandler) externalIDs(ctx context.Context) map[string]string {
	rows, err := h.svc.q.ListWorkspaceSCIMCredentials(ctx, h.workspaceID)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.UserID] = r.Subject
	}
	return out
}

// scimUserPatch reads the writable attributes off a full representation.
func scimUserPatch(attrs scim.ResourceAttributes) UpdateUserPatch {
	patch := UpdateUserPatch{}
	if name := scimDisplayName(attrs["displayName"], attrs["name"]); name != "" {
		patch.Name = &name
	}
	if active, ok := attrs["active"].(bool); ok {
		patch.Active = &active
	}
	return patch
}

func userResource(u *db.User, externalID string) scim.Resource {
	attrs := scim.ResourceAttributes{
		"userName": u.Email,
		"active":   u.Active,
		"emails": []any{map[string]any{
			"value":   u.Email,
			"type":    "work",
			"primary": true,
		}},
	}
	if u.Name != "" {
		attrs["displayName"] = u.Name
		attrs["name"] = map[string]any{"formatted": u.Name}
	}
	out := scim.Resource{
		ID:         u.ID,
		Attributes: attrs,
		Meta: scim.Meta{
			Created:      &u.CreatedAt,
			LastModified: &u.UpdatedAt,
		},
	}
	if externalID != "" {
		out.ExternalID = optional.NewString(externalID)
	}
	return out
}

func memberResource(row *db.ListWorkspaceMembersRow, externalID string) scim.Resource {
	attrs := scim.ResourceAttributes{
		"userName": row.Email,
		"active":   row.Active,
		"emails": []any{map[string]any{
			"value":   row.Email,
			"type":    "work",
			"primary": true,
		}},
	}
	if row.Name != "" {
		attrs["displayName"] = row.Name
		attrs["name"] = map[string]any{"formatted": row.Name}
	}
	out := scim.Resource{
		ID:         row.UserID,
		Attributes: attrs,
		Meta: scim.Meta{
			Created:      &row.CreatedAt,
			LastModified: &row.UpdatedAt,
		},
	}
	if externalID != "" {
		out.ExternalID = optional.NewString(externalID)
	}
	return out
}

// scimEmailValue pulls the first address out of an emails value, whichever
// of the accepted shapes the client sent.
func scimEmailValue(v any) string {
	switch emails := v.(type) {
	case []any:
		if len(emails) == 0 {
			return ""
		}
		return scimAttrString(emails[0])
	case map[string]any:
		return scimAttrString(emails["value"])
	default:
		return scimAttrString(v)
	}
}

// paginate applies RFC 7644 list pagination over an already-filtered slice.
func paginate(all []scim.Resource, params scim.ListRequestParams) scim.Page {
	total := len(all)
	start := max(params.StartIndex, 1)
	count := max(params.Count, 0)
	lo := min(start-1, total)
	hi := min(lo+count, total)
	page := all[lo:hi]
	if page == nil {
		page = []scim.Resource{}
	}
	return scim.Page{TotalResults: total, Resources: page}
}
