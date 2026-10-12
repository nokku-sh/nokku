package api

import (
	"testing"

	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

// A feature the guard enforces but the billing payload lacks leaves every client unable to show it.
func TestFeaturesProto_CoversTheCatalog(t *testing.T) {
	features := featuresProto(entitlement.Plan{})

	for _, feature := range entitlement.CatalogFeatures {
		if _, ok := features[feature.Code]; !ok {
			t.Errorf("feature %q is in the catalog but missing from the billing payload", feature)
		}
	}
}
