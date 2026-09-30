package billing

// Licenses verify offline against a compiled-in Ed25519 public key, so
// activation works air-gapped.

import (
	"os"

	"github.com/mizuchilabs/kata/licx"
)

const (
	app  = "NOKKU"
	plan = "enterprise"
)

func verifyLicense() *licx.Claims {
	if !licx.HasPublicKey() {
		return nil
	}
	key, ok := os.LookupEnv("NOKKU_LICENSE_KEY")
	if !ok {
		return nil
	}
	claims, err := licx.Verify(key, app)
	if err != nil || claims.Plan != plan {
		return nil
	}
	return claims
}
