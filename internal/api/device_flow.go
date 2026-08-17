package api

import (
	"time"

	"github.com/mizuchilabs/kagi/deviceauth"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
)

// deviceSessionTTL is how long an nk device session lasts before the user
// must re-run the browser device flow. Longer than the web session (24h) so a
// daily-driver CLI is not hitting the browser every day, but bounded because
// there is no refresh flow.
const deviceSessionTTL = 7 * 24 * time.Hour

// NewDeviceFlow builds the kagi RFC 8628 device-flow handler, with DPoP
// binding so the issued session is tied to the device's key.
func NewDeviceFlow(cfg *config.Config) (*deviceauth.Handler, error) {
	return deviceauth.New(cfg.Auth.Kagi, deviceauth.Options{
		Cache:           cfg.Cache,
		VerificationURI: cfg.FullURL() + "/device",
		DPoP:            cfg.Auth.DPoP,
		Kind:            auth.KindDevice,
		SessionTTL:      deviceSessionTTL,
	})
}
