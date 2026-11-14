package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
)

var errLockLost = errors.New("lost the server lock")

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
			// Outlives the signal, so draining requests can still audit.
			running, stop := context.WithCancel(context.WithoutCancel(ctx))
			defer stop()
			ctx, lockLost := context.WithCancelCause(ctx)
			defer lockLost(nil)
			// First, a second core must not migrate or load keys under this one.
			if err := db.HoldServerLock(ctx, running, func() { lockLost(errLockLost) }); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			cfg, err := app.New(running, cmd)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}
			// A lock lost or a signal during the load starts nothing.
			if ctx.Err() == nil {
				err = api.New(cfg).Start(ctx)
			}
			if errors.Is(context.Cause(ctx), errLockLost) {
				return errLockLost
			}
			return err
		},
		Commands: []*cli.Command{
			{
				Name:  "recover",
				Usage: "Print a sign-in link for the workspace owner",
				Description: "The way back in when the owner lost every passkey and no mail " +
					"goes out. The link works for 24 hours and replaces earlier ones. " +
					"Run it on the server with the same environment the server has.",
				Action: func(ctx context.Context, _ *cli.Command) error {
					return app.Recover(ctx)
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
					"  kms:<uri>       hcvault:// or scw-kms://\n\n" +
					"Examples:\n" +
					"  nokku rotate-secrets --new secret:NEW\n" +
					"  nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku\n\n" +
					"Pass the current kms:<uri> again after the KMS rotated its key, before " +
					"old key versions are retired there.\n\n" +
					"KMS credentials (VAULT_TOKEN, ...) are read from the environment. " +
					"Run it with the server stopped, a running one cannot read what was " +
					"re-encrypted, so it refuses otherwise. Then set NOKKU_SECRET or KMS_URI to the new value, remove " +
					"the other one and start it. The server refuses to start with the old one.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "new",
						Usage:    "Key to move to: secret:<value> or kms:<uri>",
						Required: true,
						Sources:  cli.EnvVars("NOKKU_NEW_SECRET"),
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return app.RotateSecrets(ctx, cmd.String("new"))
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
