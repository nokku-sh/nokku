package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/internal/api"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/db"
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
				Name:  "rotate-secrets",
				Usage: "Move the encryption keys under a new secret or KMS key",
				Description: "Everything at rest is encrypted by one keyset in the database, " +
					"which is wrapped by NOKKU_SECRET or by a KMS key. This command " +
					"wraps it with a new one and adds a fresh data key, in a single " +
					"transaction. No data is re-encrypted, older keys stay for " +
					"reading, so recordings stay readable.\n\n" +
					"The current key is the one the server runs with: KMS_URI when " +
					"set, NOKKU_SECRET otherwise. The new one is specified as:\n" +
					"  secret:<value>  a new NOKKU_SECRET (at least 32 characters)\n" +
					"  kms:<uri>       hcvault:// or scw-kms:// (Enterprise)\n\n" +
					"Examples:\n" +
					"  nokku rotate-secrets --new secret:NEW\n" +
					"  nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku\n\n" +
					"KMS credentials (VAULT_TOKEN, ...) are read from the environment. " +
					"Afterwards set NOKKU_SECRET or KMS_URI to the new value and restart. " +
					"The server refuses to start with the old one.",
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
					slog.Info("keys rotated, set NOKKU_SECRET or KMS_URI to the new value and restart")
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
