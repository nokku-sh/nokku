package billing

// A license is an Ed25519-signed payload encoded as a human-friendly
// NOKKU-XXXX-... string. The vendor signs with a private key kept in its
// own environment. Instances verify offline against a public key compiled
// into the binary, so activation works air-gapped.

import (
	"os"

	"github.com/mizuchilabs/kata/licx"
)

const (
	App  = "NOKKU"
	Plan = "enterprise"
)

// verifyLicense returns the validated instance license from
// NOKKU_LICENSE_KEY, or nil when absent or invalid.
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
