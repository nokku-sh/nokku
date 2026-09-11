package iam

import (
	"context"
	"errors"

	"github.com/caarlos0/env/v11"
)

type socialConfig struct {
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`
}

type adminConfig struct {
	Email    string `env:"NOKKU_ADMIN_EMAIL"`
	Password string `env:"NOKKU_ADMIN_PASSWORD"`
	Name     string `env:"NOKKU_ADMIN_NAME"`
}

// seedSocialProviders seeds the static social login providers from the
// environment credentials into sso storage.
func (s *Service) seedSocialProviders(ctx context.Context) error {
	cfg, err := env.ParseAs[socialConfig]()
	if err != nil {
		return err
	}

	seed := func(providerID, name, clientID, clientSecret string) error {
		if clientID == "" || clientSecret == "" {
			return nil
		}
		var p SSOProvider
		switch providerID {
		case "google":
			p = SSOProvider{
				ProviderID: providerID,
				Method:     MethodOIDC,
				Name:       name,
				Enabled:    true,
				OIDC: &OIDCProvider{
					IssuerURL:       "https://accounts.google.com",
					ClientID:        clientID,
					ClientSecret:    clientSecret,
					JITProvisioning: true,
				},
			}
		case "github":
			p = SSOProvider{
				ProviderID: providerID,
				Method:     MethodOAuth2,
				Name:       name,
				Enabled:    true,
				OAuth2: &OAuth2Provider{ //nolint:gosec // the secret comes from the environment, not hardcoded
					ClientID:        clientID,
					ClientSecret:    clientSecret,
					AuthURL:         "https://github.com/login/oauth/authorize",
					TokenURL:        "https://github.com/login/oauth/access_token",
					UserInfoURL:     "https://api.github.com/user",
					EmailURL:        "https://api.github.com/user/emails",
					Scopes:          []string{"read:user", "user:email"},
					JITProvisioning: true,
				},
			}
		}
		return s.PutSSOProvider(ctx, p)
	}
	if err := seed("google", "Google", cfg.GoogleClientID, cfg.GoogleClientSecret); err != nil {
		return err
	}
	return seed("github", "GitHub", cfg.GitHubClientID, cfg.GitHubClientSecret)
}

// bootstrapUser creates the first user account from the environment when
// one does not exist yet.
func (s *Service) bootstrapUser(ctx context.Context) error {
	cfg, err := env.ParseAs[adminConfig]()
	if err != nil {
		return err
	}

	if cfg.Email == "" || cfg.Password == "" {
		return nil
	}

	if _, err := s.GetUserByEmail(ctx, cfg.Email); err == nil {
		return nil // User already exists, ignore
	}

	user, err := s.Register(ctx, cfg.Email, cfg.Name, cfg.Password)
	if err != nil {
		if errors.Is(err, ErrEmailTaken) {
			return nil // Lost a race with a concurrent boot; someone else has it.
		}
		return err
	}

	// Bootstrap accounts are trusted: mark the email verified.
	return s.VerifyUserEmail(ctx, user.ID)
}
