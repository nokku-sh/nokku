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

func (s *Service) seedSocialProviders(ctx context.Context) error {
	cfg, err := env.ParseAs[socialConfig]()
	if err != nil {
		return err
	}

	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		if err := s.PutSSOProvider(ctx, SSOProvider{
			ProviderID: "google",
			Method:     MethodOIDC,
			Name:       "Google",
			Enabled:    true,
			OIDC: &OIDCProvider{
				IssuerURL:       "https://accounts.google.com",
				ClientID:        cfg.GoogleClientID,
				ClientSecret:    cfg.GoogleClientSecret,
				JITProvisioning: true,
			},
		}); err != nil {
			return err
		}
	}
	if cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "" {
		return s.PutSSOProvider(ctx, SSOProvider{
			ProviderID: "github",
			Method:     MethodOAuth2,
			Name:       "GitHub",
			Enabled:    true,
			OAuth2: &OAuth2Provider{ //nolint:gosec // the secret comes from the environment
				ClientID:        cfg.GitHubClientID,
				ClientSecret:    cfg.GitHubClientSecret,
				AuthURL:         "https://github.com/login/oauth/authorize",
				TokenURL:        "https://github.com/login/oauth/access_token",
				UserInfoURL:     "https://api.github.com/user",
				EmailURL:        "https://api.github.com/user/emails",
				Scopes:          []string{"read:user", "user:email"},
				JITProvisioning: true,
			},
		})
	}
	return nil
}

func (s *Service) bootstrapUser(ctx context.Context) error {
	cfg, err := env.ParseAs[adminConfig]()
	if err != nil {
		return err
	}

	if cfg.Email == "" || cfg.Password == "" {
		return nil
	}

	if _, err := s.GetUserByEmail(ctx, cfg.Email); err == nil {
		return nil
	}

	user, err := s.Register(ctx, cfg.Email, cfg.Name, cfg.Password)
	if err != nil {
		if errors.Is(err, ErrEmailTaken) {
			return nil // lost a race with a concurrent boot
		}
		return err
	}
	return s.VerifyUserEmail(ctx, user.ID)
}
