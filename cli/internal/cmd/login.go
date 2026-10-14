package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/client"
	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/ui"
)

func loginCMD() *cli.Command {
	return &cli.Command{
		Name:    "login",
		Usage:   "Sign in and set up ssh for your servers",
		Aliases: []string{"refresh"},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			s, err := loadState(cmd)
			if err != nil {
				return err
			}
			c, err := newClient(s)
			if err != nil {
				return err
			}
			if err = c.Sync(ctx, true); err != nil {
				return err
			}

			who := "service account"
			if s.User != nil {
				who = s.User.Email
			}
			fmt.Printf("%s Signed in as %s, %d servers available\n", ui.Green("✔"), who, len(s.Targets))
			fmt.Println("  List them with nk ls, connect with ssh <server>")
			return nil
		},
	}
}

func logoutCMD() *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Usage: "Sign out and remove local credentials, certificates, and cached state",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			s, loadErr := loadState(cmd)
			if loadErr == nil {
				c, err := client.New(s)
				if err == nil {
					err = c.Logout(ctx)
				}
				if err != nil {
					warnf("the session could not be revoked on the server, it stays valid until it expires: %v", err)
				}
			}
			ssh.StopAgent(ctx)
			if err := ssh.RemoveInclude(); err != nil {
				return err
			}
			if err := paths.RemoveConfigDir(); err != nil {
				return err
			}
			fmt.Println("Signed out. Removed credentials, certificates, and cached state")
			if loadErr == nil {
				client.OfferRemoval(s)
			}
			return nil
		},
	}
}
