package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/client"
	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/cli/internal/ui"
)

func loginCMD() *cli.Command {
	return &cli.Command{
		Name:    "login",
		Usage:   "Sign in and set up ssh for your servers",
		Aliases: []string{"refresh"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "ci",
				Usage: "Sign in a CI job as this service account, with the job's token from its platform",
			},
			&cli.BoolFlag{
				Name:  "security-key",
				Usage: "Keep the ssh key on a FIDO2 security key, every ssh login then needs a touch",
			},
			&cli.BoolFlag{
				Name:  "headless",
				Usage: "Sign in by typing a code on another device, for a machine without a browser",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			s, err := loadState(cmd)
			if err != nil {
				return err
			}
			if cmd.Bool("security-key") {
				if err = useSecurityKey(ctx, cmd, s); err != nil {
					return err
				}
			}
			c, err := newClient(s)
			if err != nil {
				return err
			}
			c.Headless = cmd.Bool("headless")
			if cmd.IsSet("ci") {
				if err = c.LoginCI(ctx, cmd.String("ci")); err != nil {
					return err
				}
			}
			// Never a browser for a job, even if its session just ended.
			if err = c.Sync(ctx, !cmd.IsSet("ci")); err != nil {
				return err
			}

			who := "service account"
			switch {
			case s.User != nil:
				who = s.User.Email
			case s.ServiceAccount != nil:
				who += " " + s.ServiceAccount.Name
			}
			fmt.Printf("%s Signed in as %s, %d servers available\n", ui.Green("✔"), who, len(s.Targets))
			fmt.Println("  List them with nk ls, connect with ssh <server>")
			return nil
		},
	}
}

// The new key reaches the core with the sign-in that follows, ensureSession ends the old session.
func useSecurityKey(ctx context.Context, cmd *cli.Command, s *state.State) error {
	if cmd.IsSet("ci") || s.IsServiceAccount() {
		return errors.New("a security key needs a person to touch it, it is not for CI or NK_TOKEN")
	}
	if err := ssh.EnrollSecurityKey(ctx); err != nil {
		return err
	}
	s.SecurityKey = true
	if err := s.Save(); err != nil {
		return err
	}
	// ssh must use the key even if the sync that follows fails.
	return ssh.WriteConfigs(s)
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
			} else {
				warnf("the session was not revoked on the server, it stays valid until it expires: %v", loadErr)
			}
			ssh.StopAgent(ctx)
			if err := ssh.RemoveInclude(); err != nil {
				return err
			}
			if err := paths.RemoveConfigDir(); err != nil {
				return err
			}
			fmt.Println("Signed out. Removed credentials, certificates, and cached state")
			return nil
		},
	}
}
