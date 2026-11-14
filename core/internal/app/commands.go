package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// AdminLink prints a sign-in link for the owner of a self-hosted server.
// It builds only db and iam, the server may be running next to it.
func AdminLink(ctx context.Context) error {
	ec, err := env.ParseAs[EnvConfig]()
	if err != nil {
		return err
	}
	if ec.SaaS {
		return errors.New("admin-link is for a self-hosted server")
	}
	conn, err := db.NewConnection(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	ws, err := conn.Sys().GetFirstWorkspace(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("there is no workspace yet, start the server once")
	}
	if err != nil {
		return err
	}
	keys, err := kms.New(ctx, conn, false)
	if err != nil {
		return err
	}
	svc, err := iam.New(ctx, iam.Deps{Conn: conn, Keyset: keys})
	if err != nil {
		return err
	}
	owner, link, err := svc.AdminLink(ctx, actor.Workspace{ID: ws.ID, Slug: ws.Slug, BaseURL: ec.FullURL()})
	if err != nil {
		return err
	}
	fmt.Printf("Sign in as %s within 24 hours:\n\n  %s\n", owner.Email, link)
	return nil
}

// RotateSecrets moves the keyset under newKey, a secret:<value> or kms:<uri>.
func RotateSecrets(ctx context.Context, newKey string) error {
	conn, err := db.NewConnection(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	// False even when hosted, the secret may still wrap it.
	keys, err := kms.New(ctx, conn, false)
	if err != nil {
		return fmt.Errorf("current keys: %w", err)
	}
	if err := keys.Rotate(ctx, newKey); err != nil {
		return fmt.Errorf("failed to rotate: %w", err)
	}
	fmt.Println("keys rotated, set NOKKU_SECRET or KMS_URI to the new value, remove the other and start the server")
	return nil
}
