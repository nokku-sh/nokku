package iam

// Shared RFC 7644 Patch operation walk for the SCIM user and group handlers.

import (
	scim "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	filter "github.com/scim2/filter-parser/v2"
)

// eachScimOp walks Patch operations and calls apply for every attribute they
// name. A path-less add or replace carries a full or partial attributes
// object, which fans out one call per entry. expr is the path's value filter
// (the members[value eq ...] form), nil for path-less operations.
func eachScimOp(
	ops []scim.PatchOperation,
	apply func(opName, attr string, expr filter.Expression, value any) error,
) error {
	for _, op := range ops {
		if op.Path == nil {
			m, ok := op.Value.(map[string]any)
			if !ok {
				return scimerrors.ScimErrorBadRequest("missing attribute path")
			}
			for attr, value := range m {
				if err := apply(op.Op, attr, nil, value); err != nil {
					return err
				}
			}
			continue
		}
		if err := apply(op.Op, op.Path.AttributePath.AttributeName, op.Path.ValueExpression, op.Value); err != nil {
			return err
		}
	}
	return nil
}
