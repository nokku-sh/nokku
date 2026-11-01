package api

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

// A feature the billing payload lacks is one no client can show.
func TestFeaturesProto_CoversTheCatalog(t *testing.T) {
	features := featuresProto(entitlement.Plan{})

	for _, feature := range entitlement.CatalogFeatures {
		assert.Contains(t, features, feature.Code,
			"feature %q is in the catalog but missing from the billing payload", feature.Code)
	}
}
