package api

import (
	"github.com/mizuchilabs/kagi/oidc"

	"github.com/nokku-sh/nokku/internal/config"
)

// NewOIDCHandler builds the kagi OIDC handler for nokku's providers: the
// static google social provider and workspace enterprise providers resolved
// through the policy hooks.
func NewOIDCHandler(cfg *config.Config) (*oidc.Handler, error) {
	return oidc.New(cfg.Auth.Kagi, oidc.Options{
		Cache:         cfg.Cache,
		ErrorRedirect: cfg.FullURL() + "/auth-error",
	})
}
