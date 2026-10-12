package cmd

import (
	"context"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/nk/internal/doctor"
)

func doctorCMD() *cli.Command {
	return &cli.Command{
		Name:  "doctor",
		Usage: "Check your setup and explain how to fix problems",
		Flags: []cli.Flag{
			jsonFlag,
			&cli.BoolFlag{Name: "fix", Usage: "Repair the ssh config, permissions, and stale certificates"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			s, err := loadState(cmd)
			if err != nil {
				return err
			}
			report := doctor.Run(ctx, s, cmd.Bool("fix"))
			if cmd.Bool(jsonFlag.Name) {
				if err = printJSON(report); err != nil {
					return err
				}
			} else {
				doctor.Print(os.Stdout, report)
			}
			if code := report.ExitCode(); code != 0 {
				return cli.Exit("doctor found issues", code)
			}
			return nil
		},
	}
}
