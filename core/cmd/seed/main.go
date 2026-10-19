// Command seed fills the first workspace of a dev database with fake data, or with users who can sign in.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
)

func main() {
	cmd := &cli.Command{
		Name:  "nokku-seed",
		Usage: "fill the first workspace with fake data, for development",
		Description: "Run it with the environment the server has, the server may be " +
			"running. Every run adds to what is there. The users have no way to " +
			"sign in and the daemons never connect.",
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "users", Value: 8, Usage: "number of users"},
			&cli.IntFlag{Name: "teams", Value: 5, Usage: "number of teams"},
			&cli.IntFlag{Name: "service-accounts", Value: 5, Usage: "number of service accounts"},
			&cli.IntFlag{Name: "cas", Value: 2, Usage: "number of SSH certificate authorities"},
			&cli.IntFlag{Name: "targets", Value: 5, Usage: "number of servers without a daemon"},
			&cli.IntFlag{Name: "daemons", Value: 5, Usage: "number of daemons, each with its server"},
		},
		Action: run,
		Commands: []*cli.Command{{
			Name:  "idp",
			Usage: "set up sign-ins against the Pocket ID of compose.dev.yml",
			Description: "It waits for the server, then adds Pocket ID as a provider, fills Pocket ID " +
				"with users and groups, and has it send them over SCIM. The owner is linked to " +
				"admin@nokku.test. task dev runs it.",
			Action: runIDP,
		}},
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	ec, err := env.ParseAs[config.EnvConfig]()
	if err != nil {
		return err
	}
	ctx, conn, ws, err := open(ctx, ec)
	if err != nil {
		return err
	}
	n := counts{
		users:           cmd.Int("users"),
		teams:           cmd.Int("teams"),
		serviceAccounts: cmd.Int("service-accounts"),
		cas:             cmd.Int("cas"),
		targets:         cmd.Int("targets"),
		daemons:         cmd.Int("daemons"),
	}
	err = conn.TenantTx(ctx, func(q *db.Queries) error {
		return seed(ctx, q, ws, n)
	})
	// The names are random, now and then one is taken already.
	if db.IsUniqueViolation(err) || errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("a generated name is taken, nothing was written, run it again: %w", err)
	}
	if err != nil {
		return err
	}
	fmt.Printf(
		"%s got %d users, %d teams, %d service accounts, %d CAs, %d servers and %d daemons\n",
		ws.Name, n.users, n.teams, n.serviceAccounts, n.cas, n.targets, n.daemons,
	)
	return nil
}

// open takes only the database and the keys, the server may be running next to this. The ctx carries the first workspace.
func open(ctx context.Context, ec config.EnvConfig) (context.Context, *db.Connection, *db.Workspace, error) {
	conn, err := db.NewConnection(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	ws, err := conn.Sys().GetFirstWorkspace(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil, errors.New("there is no workspace yet, start the server once")
	}
	if err != nil {
		return nil, nil, nil, err
	}
	// Keys and provider secrets are encrypted on their way into the database.
	enc, err := kms.New(ctx, conn, ec.Secret)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := crypto.SetEncryptor(enc); err != nil {
		return nil, nil, nil, err
	}
	ctx = actor.WithWorkspace(ctx, actor.Workspace{ID: ws.ID, Slug: ws.Slug, BaseURL: ec.FullURL()})
	return ctx, conn, ws, nil
}
