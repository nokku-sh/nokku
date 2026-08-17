package api

import (
	"github.com/mizuchilabs/kagi/oauth2"

	"github.com/nokku-sh/nokku/internal/config"
)

// NewOAuthHandler builds the kagi OAuth2 handler for the static GitHub social
// provider.
func NewOAuthHandler(cfg *config.Config) (*oauth2.Handler, error) {
	return oauth2.New(cfg.Auth.Kagi, oauth2.Options{
		Cache:         cfg.Cache,
		ErrorRedirect: cfg.FullURL() + "/auth-error",
	})
}
