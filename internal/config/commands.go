package config

import (
	"context"
	"errors"

	"github.com/caarlos0/env/v11"
	"github.com/mizuchilabs/kagi"
)

type AdminConfig struct {
	Email    string `env:"NOKKU_ADMIN_EMAIL"`
	Password string `env:"NOKKU_ADMIN_PASSWORD"`
	Name     string `env:"NOKKU_ADMIN_NAME"`
}

// BootstrapAdmin creates the first admin account from the environment when
// one does not exist yet. Identity is kagi's; the password manager is the
// same one the mounted login flow uses.
func (c *Config) BootstrapAdmin(ctx context.Context) error {
	cfg, err := env.ParseAs[AdminConfig]()
	if err != nil {
		return err
	}

	if cfg.Email == "" || cfg.Password == "" {
		return nil
	}

	svc := c.Auth.Service()
	if _, err := svc.Store.GetUserByEmail(ctx, "", cfg.Email); err == nil {
		return nil // User already exists, ignore
	}

	admin, err := svc.Store.CreateUser(ctx, "", kagi.User{
		Email:         cfg.Email,
		DisplayName:   cfg.Name,
		Active:        true,
		EmailVerified: true,
	})
	if err != nil {
		if errors.Is(err, kagi.ErrEmailTaken) {
			return nil // Lost a race with a concurrent boot; someone else has it.
		}
		return err
	}

	return c.Auth.Service().Passwords.SetPassword(ctx, "", admin.ID, cfg.Password)
}
