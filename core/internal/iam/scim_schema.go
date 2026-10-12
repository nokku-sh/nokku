package iam

// Attributes without a backing column are left out, so the library rejects them instead of dropping data.

import (
	scim "github.com/elimity-com/scim"
	"github.com/elimity-com/scim/optional"
	"github.com/elimity-com/scim/schema"

	"github.com/nokku-sh/nokku/core/internal/actor"
)

const (
	scimUserEndpoint  = "/Users"
	scimGroupEndpoint = "/Groups"
)

func scimUserSchema() schema.Schema {
	return schema.Schema{
		ID:          "urn:ietf:params:scim:schemas:core:2.0:User",
		Name:        optional.NewString("User"),
		Description: optional.NewString("User Account"),
		Attributes: []schema.CoreAttribute{
			schema.SimpleCoreAttribute(schema.SimpleStringParams(schema.StringParams{
				Name:       "userName",
				Required:   true,
				Uniqueness: schema.AttributeUniquenessServer(),
			})),
			schema.SimpleCoreAttribute(schema.SimpleBooleanParams(schema.BooleanParams{
				Name: "active",
			})),
			schema.SimpleCoreAttribute(schema.SimpleStringParams(schema.StringParams{
				Name: "displayName",
			})),
			schema.ComplexCoreAttribute(schema.ComplexParams{
				Name: "name",
				SubAttributes: []schema.SimpleParams{
					schema.SimpleStringParams(schema.StringParams{Name: "formatted"}),
					schema.SimpleStringParams(schema.StringParams{Name: "givenName"}),
					schema.SimpleStringParams(schema.StringParams{Name: "familyName"}),
				},
			}),
			schema.ComplexCoreAttribute(schema.ComplexParams{
				Name:        "emails",
				MultiValued: true,
				SubAttributes: []schema.SimpleParams{
					schema.SimpleStringParams(schema.StringParams{Name: "value"}),
					schema.SimpleStringParams(schema.StringParams{Name: "type"}),
					schema.SimpleBooleanParams(schema.BooleanParams{Name: "primary"}),
				},
			}),
		},
	}
}

func scimGroupSchema() schema.Schema {
	return schema.Schema{
		ID:          "urn:ietf:params:scim:schemas:core:2.0:Group",
		Name:        optional.NewString("Group"),
		Description: optional.NewString("Group"),
		Attributes: []schema.CoreAttribute{
			schema.SimpleCoreAttribute(schema.SimpleStringParams(schema.StringParams{
				Name:     "displayName",
				Required: true,
			})),
			schema.ComplexCoreAttribute(schema.ComplexParams{
				Name:        "members",
				MultiValued: true,
				SubAttributes: []schema.SimpleParams{
					schema.SimpleStringParams(schema.StringParams{Name: "value"}),
					schema.SimpleStringParams(schema.StringParams{Name: "display"}),
					schema.SimpleStringParams(schema.StringParams{Name: "$ref"}),
				},
			}),
		},
	}
}

func scimResourceTypes(svc *Service, ws actor.Workspace) []scim.ResourceType {
	return []scim.ResourceType{
		{
			ID:       optional.NewString("User"),
			Name:     "User",
			Endpoint: scimUserEndpoint,
			Schema:   scimUserSchema(),
			Handler:  scimUserHandler{svc: svc, ws: ws},
		},
		{
			ID:       optional.NewString("Group"),
			Name:     "Group",
			Endpoint: scimGroupEndpoint,
			Schema:   scimGroupSchema(),
			Handler:  scimGroupHandler{svc: svc, ws: ws},
		},
	}
}
