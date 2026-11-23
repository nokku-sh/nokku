package cmd

import (
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

const (
	requestPollFirst = 3 * time.Second
	requestPollLast  = 30 * time.Second
)

func requestCMD() *cli.Command {
	return &cli.Command{
		Name:      "request",
		Usage:     "Ask for an account on a server, for a while",
		ArgsUsage: "<account>@<server>",
		Flags: []cli.Flag{
			&cli.DurationFlag{Name: "for", Value: time.Hour, Usage: "How long you need it, from 15m to 168h"},
			&cli.StringFlag{Name: "reason", Aliases: []string{"r"}, Usage: "Why you need it, whoever answers reads it"},
			&cli.BoolFlag{Name: "no-wait", Usage: "Return once the request is sent"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			account, server, ok := strings.Cut(cmd.Args().First(), "@")
			if !ok || cmd.NArg() != 1 || cmd.String("reason") == "" {
				return errors.New(`usage: nk request <account>@<server> --reason "..." [--for 2h]`)
			}
			server = strings.TrimSuffix(server, ssh.HostSuffix)
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
				fmt.Println("  You get an email with the answer. Then ssh as usual.")
				return nil
			}
			fmt.Println("  Waiting for an answer. Ctrl-C stops waiting, the request stays open for a week.")
			return waitForAnswer(ctx, c, req.GetId())
		},
	}
}

func waitForAnswer(ctx context.Context, c *client.Client, id string) error {
	for wait := requestPollFirst; ; wait = min(wait*2, requestPollLast) {
		select {
		case <-ctx.Done():
			fmt.Println("\n  Stopped waiting. Once it is approved, ssh as usual.")
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
			// The sync brings the account. A cert without it gets signed again.
			if err = c.Sync(ctx, false); err != nil {
				return err
			}
			host := ssh.HostName(ui.PlainLine(req.GetTargetName()))
			fmt.Printf("%s Approved by %s until %s\n", ui.Green("✔"), ui.PlainLine(req.GetDeciderName()),
				untilLabel(req.GetGrantedUntil().AsTime()))
			fmt.Printf("  Connect with: ssh %s@%s\n", req.GetUsername(), host)
			return nil
		}
		state := strings.ToLower(strings.TrimPrefix(req.GetStatus().String(), "ACCESS_REQUEST_STATUS_"))
		if reason := ui.PlainLine(req.GetDecisionReason()); reason != "" {
			return fmt.Errorf("the request was %s by %s: %s", state, ui.PlainLine(req.GetDeciderName()), reason)
		}
		return fmt.Errorf("the request was %s", state)
	}
}
