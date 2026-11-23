package iam

import (
	"cmp"
	"strings"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	filter "github.com/scim2/filter-parser/v2"
)

// scimNames holds the names the handlers read, by their lower case. A provider may send any case (RFC 7643 2.1).
var scimNames = map[string]string{
	"active":      "active",
	"displayname": "displayName",
	"emails":      "emails",
	"externalid":  "externalId",
	"familyname":  "familyName",
	"formatted":   "formatted",
	"givenname":   "givenName",
	"members":     "members",
	"name":        "name",
	"primary":     "primary",
	"type":        "type",
	"username":    "userName",
	"value":       "value",
}

// eachScimOp fans a path-less op out to one call per attribute.
func eachScimOp(
	ops []scim.PatchOperation,
	apply func(opName, attr string, expr filter.Expression, value any) error,
) error {
	for _, op := range ops {
		value := op.Value
		if op.Path != nil {
			// Give a sub-attribute the path-less shape, handlers read one form.
			if sub := cmp.Or(op.Path.SubAttributeName(), op.Path.AttributePath.SubAttributeName()); sub != "" {
				value = map[string]any{scimName(sub): value}
			}
			attr := scimName(op.Path.AttributePath.AttributeName)
			if err := apply(op.Op, attr, op.Path.ValueExpression, value); err != nil {
				return err
			}
			continue
		}
		m, ok := value.(map[string]any)
		if !ok {
			return scimerrors.ScimErrorBadRequest("missing attribute path")
		}
		for attr, value := range m {
			if err := apply(op.Op, scimName(attr), nil, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func scimName(name string) string {
	return cmp.Or(scimNames[strings.ToLower(name)], name)
}
