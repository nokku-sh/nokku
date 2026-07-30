package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/nokku-sh/nokku/internal/api"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/testutil"
	"github.com/urfave/cli/v3"
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
				Name:   "seed",
				Usage:  "Seed the database with test data",
				Hidden: true,
				Action: func(ctx context.Context, cmd *cli.Command) error {
					cfg, err := config.New(ctx, cmd)
					if err != nil {
						return fmt.Errorf("failed to load configuration: %w", err)
					}
					return testutil.SeedWorkspace(ctx, cfg.Conn)
				},
			},
			{
				Name:  "rotate-secrets",
				Usage: "Re-encrypt all DB secrets onto a new cipher",
				Description: "Migrates every encrypted value (CA private keys, OIDC client secrets, " +
					"SAML private keys) onto a new cipher, in a single transaction: if anything " +
					"fails, nothing changes and the command can simply be re-run.\n\n" +
					"The current cipher is whatever the app decrypts with today, taken from the " +
					"environment (NOKKU_SECRET, or KMS_URI with the keyset stored in the database). " +
					"The new cipher is specified as:\n" +
					"  secret:<value>   self-hosted secretbox key\n" +
					"  kms:<uri>        KMS-backed envelope encryption (hcvault://..., scw-kms://..., ...)\n\n" +
					"Examples:\n" +
					"  nokku rotate-secrets --new secret:NEW\n" +
					"  nokku rotate-secrets --new kms:scw-kms://regions/fr-par/keys/KEY_ID\n\n" +
					"KMS credentials (VAULT_TOKEN, Scaleway profile, ...) are read from the environment. " +
					"Run this with the app stopped, then update the environment and start it again.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "new",
						Usage:    "Cipher to migrate to: secret:<value> or kms:<uri>",
						Required: true,
						Sources:  cli.EnvVars("NOKKU_NEW_CIPHER"),
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

					// The old cipher is whatever the app currently decrypts with.
					var oldCipher crypto.Cipher
					if secret := os.Getenv("NOKKU_SECRET"); secret != "" {
						oldCipher, err = crypto.NewSecretbox([]byte(secret))
					} else {
						oldCipher, err = kms.New(ctx, conn)
					}
					if err != nil {
						return fmt.Errorf("current cipher: %w", err)
					}

					// The new cipher, plus the hook that finalizes the switch
					// inside the rotation transaction: a KMS target persists its
					// fresh keyset, a secretbox target drops the keyset row.
					var newCipher crypto.Cipher
					var finalize func(ctx context.Context, q *db.Queries) error
					if secret, ok := strings.CutPrefix(cmd.String("new"), "secret:"); ok &&
						secret != "" {
						newCipher, err = crypto.NewSecretbox([]byte(secret))
						if err != nil {
							return fmt.Errorf("new cipher: %w", err)
						}
						finalize = func(ctx context.Context, q *db.Queries) error {
							return q.DeleteKeyset(ctx)
						}
					} else if uri, ok := strings.CutPrefix(cmd.String("new"), "kms:"); ok &&
						uri != "" {
						enc, err := kms.NewForRotation(ctx, uri)
						if err != nil {
							return fmt.Errorf("new cipher: %w", err)
						}
						data, err := enc.WrappedKeyset()
						if err != nil {
							return fmt.Errorf("new cipher: %w", err)
						}
						newCipher = enc
						finalize = func(ctx context.Context, q *db.Queries) error {
							return q.UpsertKeysetWrappedData(ctx, data)
						}
					} else {
						return fmt.Errorf(
							"invalid cipher %q: must be secret:<value> or kms:<uri>",
							cmd.String("new"),
						)
					}

					// Decrypt via the old cipher, re-encrypt via the new one, and
					// swap the keyset — atomically, in one transaction.
					rotating, err := crypto.NewRotatingCipher(newCipher, oldCipher)
					if err != nil {
						return fmt.Errorf("failed to create rotating cipher: %w", err)
					}
					if err := crypto.SetEncryptor(rotating); err != nil {
						return err
					}
					if err := db.RotateSecrets(ctx, conn, finalize); err != nil {
						return fmt.Errorf("failed to rotate secrets: %w", err)
					}

					slog.Info(
						"Successfully rotated secrets, update the environment and restart the app",
					)
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
