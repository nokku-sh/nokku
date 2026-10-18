package cmd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/cli/internal/client"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/ui"
)

// A request may wait a day, so the poll slows down from the first to the last interval.
const (
	requestPollFirst = 3 * time.Second
	requestPollLast  = 30 * time.Second
)

func requestCMD() *cli.Command {
	return &cli.Command{
		Name:      "request",
		Usage:     "Ask an admin for an account on a server, for a while",
		ArgsUsage: "<server> <account>",
		Flags: []cli.Flag{
			&cli.DurationFlag{Name: "for", Value: time.Hour, Usage: "How long you need it, from 15m to 168h"},
			&cli.StringFlag{Name: "reason", Aliases: []string{"r"}, Usage: "Why you need it, the admins see it"},
			&cli.BoolFlag{Name: "no-wait", Usage: "Return once the request is sent"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.NArg() != 2 || cmd.String("reason") == "" {
				return errors.New(`usage: nk request <server> <account> --reason "..." [--for 2h]`)
			}
			server, account := cmd.Args().Get(0), cmd.Args().Get(1)
			c, err := connect(ctx, cmd)
			if err != nil {
				return err
			}
			req, err := c.RequestAccess(ctx, server, account, cmd.Duration("for"), cmd.String("reason"))
			if err != nil {
				return err
			}
			fmt.Printf("%s Asked for %s on %s for %s\n",
				ui.Green("✔"), account, ui.PlainLine(req.GetTargetName()), ui.HumanizeDuration(cmd.Duration("for")))
			if cmd.Bool("no-wait") {
				fmt.Println("  You get an email with the answer. Then run nk login and ssh as usual.")
				return nil
			}
			fmt.Println("  Waiting for an admin. Ctrl-C stops waiting, the request stays open.")
			return waitForAnswer(ctx, c, req.GetId())
		},
	}
}

func waitForAnswer(ctx context.Context, c *client.Client, id string) error {
	for wait := requestPollFirst; ; wait = min(wait*2, requestPollLast) {
		select {
		case <-ctx.Done():
			fmt.Println("\n  Stopped waiting. Run nk login once it is approved.")
			return nil
		case <-time.After(wait):
		}
		req, err := c.AccessRequest(ctx, id)
		if err != nil {
			return err
		}
		//nolint:exhaustive // every answer but approved ends the wait the same way
		switch req.GetStatus() {
		case nokkuv1.AccessRequestStatus_ACCESS_REQUEST_STATUS_PENDING:
			continue
		case nokkuv1.AccessRequestStatus_ACCESS_REQUEST_STATUS_APPROVED:
			// The account comes with the next sync, and a cached certificate without it is signed again.
			if err = c.Sync(ctx, false); err != nil {
				return err
			}
			host := cmp.Or(ssh.HostAliases(c.State)[req.GetTargetId()], ui.PlainLine(req.GetTargetName()))
			fmt.Printf("%s Approved by %s until %s\n", ui.Green("✔"), ui.PlainLine(req.GetDeciderName()),
				untilLabel(req.GetGrantedUntil().AsTime()))
			fmt.Printf("  Connect with: ssh %s@%s\n", req.GetUsername(), host)
			return nil
		}
		return fmt.Errorf("the request was %s",
			strings.ToLower(strings.TrimPrefix(req.GetStatus().String(), "ACCESS_REQUEST_STATUS_")))
	}
}
