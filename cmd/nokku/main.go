package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/api"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

func main() {
	cmd := &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nokku",
		Version:               buildinfo.String(),
		Usage:                 "access management server",
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logx.Init(cmd.Bool("debug"))
			return ctx, nil
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := config.New(ctx, cmd)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}
			return api.New(cfg).Start(ctx)
		},
		Commands: []*cli.Command{
			{
				Name:  "admin-link",
				Usage: "Print a sign-in link for the workspace owner",
				Description: "The way back in when the owner lost every passkey and no mail " +
					"goes out. The link works for 24 hours and replaces earlier ones. " +
					"Run it on the server with the same environment the server has.",
				// Only the database and iam. The server may be running next to
				// this, so nothing of what it does at boot happens here.
				Action: func(ctx context.Context, _ *cli.Command) error {
					ec, err := env.ParseAs[config.EnvConfig]()
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
					svc, err := iam.New(ctx, iam.Deps{Conn: conn, Secret: []byte(ec.Secret)})
					if err != nil {
						return err
					}
					owner, link, err := svc.AdminLink(
						ctx,
						actor.Workspace{ID: ws.ID, Slug: ws.Slug, BaseURL: ec.FullURL()},
					)
					if err != nil {
						return err
					}
					fmt.Printf("Sign in as %s within 24 hours:\n\n  %s\n", owner.Email, link)
					return nil
				},
			},
			{
				Name:  "rotate-secrets",
				Usage: "Move the encryption keys under a new secret or KMS key",
				Description: "The secrets in the database are encrypted by one keyset, which " +
					"is wrapped by NOKKU_SECRET or by a KMS key. This command wraps it " +
					"with a new one, adds a fresh data key, re-encrypts the secrets " +
					"with it and drops the older keys, in a single transaction. " +
					"Recordings are not re-encrypted, only their keys are.\n\n" +
					"The current key is the one the server runs with: KMS_URI when " +
					"set, NOKKU_SECRET otherwise. The new one is specified as:\n" +
					"  secret:<value>  a new NOKKU_SECRET (at least 32 characters)\n" +
					"  kms:<uri>       hcvault:// or scw-kms:// (Enterprise)\n\n" +
					"Examples:\n" +
					"  nokku rotate-secrets --new secret:NEW\n" +
					"  nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku\n\n" +
					"KMS credentials (VAULT_TOKEN, ...) are read from the environment. " +
					"Run it with the server stopped, a running one cannot read what was " +
					"re-encrypted. Then set NOKKU_SECRET or KMS_URI to the new value and " +
					"start it. The server refuses to start with the old one.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "new",
						Usage:    "Key to move to: secret:<value> or kms:<uri>",
						Required: true,
						Sources:  cli.EnvVars("NOKKU_NEW_SECRET"),
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					conn, err := db.NewConnection(ctx)
					if err != nil {
						return fmt.Errorf("failed to connect to database: %w", err)
					}
					if conn.Pool != nil {
						defer conn.Pool.Close()
					}
					ec, err := env.ParseAs[config.EnvConfig]()
					if err != nil {
						return err
					}
					enc, err := kms.New(ctx, conn, ec.Secret)
					if err != nil {
						return fmt.Errorf("current keys: %w", err)
					}
					if err := enc.Rotate(ctx, cmd.String("new")); err != nil {
						return fmt.Errorf("failed to rotate: %w", err)
					}
					fmt.Println("keys rotated, set NOKKU_SECRET or KMS_URI to the new value and start the server")
					return nil
				},
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "debug",
				Aliases: []string{"d"},
				Usage:   "Enable debug logging",
				Sources: cli.EnvVars("NOKKU_DEBUG"),
			},
		},
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}
