package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/pkg/seed"
)

func main() {
	defaults := seed.DefaultConfig()
	cmd := &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nokku-seed",
		Version:               buildinfo.String(),
		Usage:                 "seed a nokku database with demo data",
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logx.Init(cmd.Bool("debug"))
			return ctx, nil
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "debug",
				Aliases: []string{"d"},
				Usage:   "Enable debug logging",
				Sources: cli.EnvVars("NOKKU_DEBUG"),
			},
			&cli.IntFlag{Name: "users", Value: defaults.NumUsers, Usage: "number of users"},
			&cli.IntFlag{Name: "teams", Value: defaults.NumTeams, Usage: "number of teams"},
			&cli.IntFlag{Name: "targets", Value: defaults.NumTargets, Usage: "number of targets"},
			&cli.IntFlag{Name: "daemons", Value: defaults.NumDaemons, Usage: "number of daemons"},
			&cli.IntFlag{
				Name:  "cas",
				Value: defaults.NumCAs,
				Usage: "number of certificate authorities",
			},
			&cli.IntFlag{
				Name:  "service-accounts",
				Value: defaults.NumServiceAccounts,
				Usage: "number of service accounts",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := config.New(ctx, cmd)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}
			return seed.Workspace(ctx, cfg.Conn, seed.Config{
				NumUsers:           cmd.Int("users"),
				NumTeams:           cmd.Int("teams"),
				NumTargets:         cmd.Int("targets"),
				NumDaemons:         cmd.Int("daemons"),
				NumCAs:             cmd.Int("cas"),
				NumServiceAccounts: cmd.Int("service-accounts"),
			})
		},
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}
