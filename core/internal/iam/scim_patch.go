package iam

import (
	"cmp"

	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	filter "github.com/scim2/filter-parser/v2"
)

// eachScimOp fans a path-less op out to one call per attribute.
func eachScimOp(
	ops []scim.PatchOperation,
	apply func(opName, attr string, expr filter.Expression, value any) error,
) error {
	for _, op := range ops {
		if op.Path != nil {
			// Give a sub-attribute the path-less shape, handlers read one form.
			value := op.Value
			if sub := cmp.Or(op.Path.SubAttributeName(), op.Path.AttributePath.SubAttributeName()); sub != "" {
				value = map[string]any{sub: value}
			}
			if err := apply(op.Op, op.Path.AttributePath.AttributeName, op.Path.ValueExpression, value); err != nil {
				return err
			}
			continue
		}
		m, ok := op.Value.(map[string]any)
		if !ok {
			return scimerrors.ScimErrorBadRequest("missing attribute path")
		}
		for attr, value := range m {
			if err := apply(op.Op, attr, nil, value); err != nil {
				return err
			}
		}
	}
	return nil
}
