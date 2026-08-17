package config

import (
	"context"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/internal/db"
)

type AdminConfig struct {
	Name     string `env:"NOKKU_ADMIN_NAME"     envDefault:"Nokku Admin"`
	Username string `env:"NOKKU_ADMIN_USERNAME" envDefault:"admin"`
	Email    string `env:"NOKKU_ADMIN_EMAIL"`
	Password string `env:"NOKKU_ADMIN_PASSWORD"`
}

func (c *Config) BootstrapAdmin(ctx context.Context) error {
	cfg, err := env.ParseAs[AdminConfig]()
	if err != nil {
		return err
	}

	if cfg.Email == "" || cfg.Password == "" {
		return nil
	}

	if _, err := c.Conn.Q.GetUserByEmail(ctx, cfg.Email); err == nil {
		return nil // User already exists, ignore
	}

	admin, err := c.Conn.Q.CreateUser(ctx, &db.CreateUserParams{
		Name:     cfg.Name,
		Username: cfg.Username,
		Email:    cfg.Email,
	})
	if err != nil {
		return err
	}

	if err := c.Auth.Passwords.SetPassword(ctx, "", admin.ID, cfg.Password); err != nil {
		return err
	}

	return c.Conn.Q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
		UserID: admin.ID,
		Email:  admin.Email,
	})
}
