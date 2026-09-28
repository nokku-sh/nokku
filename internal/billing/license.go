package billing

// Licenses verify offline against a compiled-in Ed25519 public key, so
// activation works air-gapped.

import (
	"os"

	"github.com/mizuchilabs/kata/licx"
)

const (
	App  = "NOKKU"
	Plan = "enterprise"
)

func verifyLicense() *licx.Claims {
	if !licx.HasPublicKey() {
		return nil
	}
	key, ok := os.LookupEnv("NOKKU_LICENSE_KEY")
	if !ok {
		return nil
	}
	claims, err := licx.Verify(key, App)
	if err != nil || claims.Plan != Plan {
		return nil
	}
	return claims
}
