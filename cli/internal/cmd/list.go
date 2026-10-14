package cmd

import (
	"cmp"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/cli/internal/ui"
)

func listCMD() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"ls"},
		Usage:   "List the servers you can connect to",
		Flags:   []cli.Flag{jsonFlag},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			c, err := connect(ctx, cmd)
			if err != nil {
				return err
			}
			s := c.State
			// The name ssh knows a server by carries a prefix when the bare one is taken.
			aliases := ssh.HostAliases(s)
			if cmd.Bool(jsonFlag.Name) {
				return printJSON(listJSON(s, aliases))
			}
			if len(s.Targets) == 0 {
				fmt.Println("You have no servers yet. Ask an admin for access.")
				return nil
			}

			for _, t := range s.Targets {
				users := ui.Dim("no accounts")
				if len(t.Usernames) > 0 {
					users = strings.Join(t.Usernames, ", ")
				}
				name := cmp.Or(aliases[t.ID], t.Name)
				fmt.Printf("  %-24s %s %s\n", name, users, ui.Dim(manualNote(t, s.CAByID(t.CAID))))
			}
			fmt.Println("\nConnect with: ssh <server> or ssh <user>@<server>")
			return nil
		},
	}
}

func manualNote(t state.Target, ca *state.CA) string {
	if !t.Manual() {
		return ""
	}
	last := t.LastManualSync()
	if last.IsZero() {
		return "(manual, never synced)"
	}
	if t.NeedsSync(ca) && ca.RotatedAt.After(last) {
		return "(manual, needs nk sync, its certificate authority was rotated)"
	}
	if t.NeedsSync(ca) {
		return "(manual, needs nk sync, it still trusts a retired certificate authority key)"
	}
	return "(manual, synced " + ui.HumanizeDuration(time.Since(last)) + " ago)"
}

func listJSON(s *state.State, aliases map[string]string) any {
	type listedTarget struct {
		Name string `json:"name"`
		// Host is what ssh knows the target by, empty when it stays out of ssh_config.
		Host       string   `json:"host,omitempty"`
		Users      []string `json:"users"`
		Manual     bool     `json:"manual"`
		LastSynced string   `json:"last_synced,omitempty"`
		NeedsSync  bool     `json:"needs_sync,omitzero"`
	}
	out := struct {
		Targets []listedTarget `json:"targets"`
	}{Targets: make([]listedTarget, 0, len(s.Targets))}
	for _, t := range s.Targets {
		out.Targets = append(out.Targets, listedTarget{
			Name:       t.Name,
			Host:       aliases[t.ID],
			Users:      append([]string{}, t.Usernames...),
			Manual:     t.Manual(),
			LastSynced: t.Metadata["last_manual_sync"],
			NeedsSync:  t.NeedsSync(s.CAByID(t.CAID)),
		})
	}
	return out
}
