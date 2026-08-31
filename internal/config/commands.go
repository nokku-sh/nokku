package config

import (
	"context"
	"errors"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/internal/iam"
)

type AdminConfig struct {
	Email    string `env:"NOKKU_ADMIN_EMAIL"`
	Password string `env:"NOKKU_ADMIN_PASSWORD"`
	Name     string `env:"NOKKU_ADMIN_NAME"`
}

// BootstrapAdmin creates the first admin account from the environment when
// one does not exist yet. The password manager is the same one the mounted
// login flow uses.
func (c *Config) BootstrapAdmin(ctx context.Context) error {
	cfg, err := env.ParseAs[AdminConfig]()
	if err != nil {
		return err
	}

	if cfg.Email == "" || cfg.Password == "" {
		return nil
	}

	if _, err := c.IAM.GetUserByEmail(ctx, cfg.Email); err == nil {
		return nil // User already exists, ignore
	}

	admin, err := c.IAM.Register(ctx, cfg.Email, cfg.Name, cfg.Password)
	if err != nil {
		if errors.Is(err, iam.ErrEmailTaken) {
			return nil // Lost a race with a concurrent boot; someone else has it.
		}
		return err
	}

	// Bootstrap accounts are trusted: mark the email verified.
	return c.IAM.VerifyUserEmail(ctx, admin.ID)
}
