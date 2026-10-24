package cmd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/client"
	"github.com/nokku-sh/nokku/cli/internal/manual"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/cli/internal/ui"
)

var portFlag = &cli.StringFlag{Name: "port", Usage: "SSH port of the server, defaults to your ssh config or 22"}

func syncCMD() *cli.Command {
	return &cli.Command{
		Name:  "sync",
		Usage: "Add a server to Nokku without the daemon, or refresh one you added",
		Description: "Connects as root with your own ssh, then writes the Nokku CA, an sshd drop-in, " +
			"and one principals file per account. Run it again whenever access changes.",
		ArgsUsage: "<host | root@host | target-name>",
		// A --grant lists its subjects with commas.
		DisableSliceFlagSeparator: true,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "Name for a new target, generated when empty"},
			&cli.StringFlag{
				Name:  "ca",
				Usage: "Certificate authority id or name for a new target, defaults to the default one",
			},
			&cli.StringSliceFlag{
				Name: "grant",
				Usage: "Who may log in to a new target, as account=subject,subject. " +
					"A subject is me, an email, team:<name>, or sa:<name>",
			},
			&cli.StringSliceFlag{Name: "tag", Usage: "Tag for a new target"},
			portFlag,
			&cli.BoolFlag{Name: "dry-run", Usage: "Show what would be written and change nothing"},
			&cli.BoolFlag{
				Name:  "accept-host-key",
				Usage: "Go on when the host key changed since the last sync and pin the new one",
			},
			jsonFlag,
		},
		Action: targetSync,
	}
}

func targetSync(ctx context.Context, cmd *cli.Command) error {
	host, err := rootHost(cmd)
	if err != nil {
		return err
	}

	c, err := connect(ctx, cmd)
	if err != nil {
		return err
	}
	dryRun := cmd.Bool("dry-run")
	asJSON := cmd.Bool(jsonFlag.Name)
	// With --json stdout carries only the result, progress goes to stderr.
	var progress io.Writer = os.Stdout
	if asJSON {
		progress = os.Stderr
	}

	target, dest, err := findRemoteTarget(ctx, c, remote{host: host, port: cmd.String("port")})
	if err != nil {
		return err
	}
	var ca *state.CA
	var seeds []client.Grant
	if target == nil {
		if target, ca, err = newTarget(ctx, c, cmd, dest); err != nil {
			return err
		}
		if seeds, err = c.ResolveGrants(ctx, cmd.StringSlice("grant")); err != nil {
			return err
		}
	} else {
		if cmd.IsSet("grant") || cmd.IsSet("tag") {
			// The web app owns access from the first sync on, so a rerun never undoes a change made there.
			warnf("%s is already a target, --grant and --tag only apply to a new one", target.Name)
		}
		if ca, err = targetCA(ctx, c, target.CAID); err != nil {
			return err
		}
	}
	if ca == nil || strings.TrimSpace(ca.PublicKey) == "" {
		return fmt.Errorf("the certificate authority of %s is missing, run nk login and try again", target.Name)
	}

	if dest, err = dest.trust(target, cmd.Bool("accept-host-key")); err != nil {
		return err
	}
	defer dest.close(ctx)

	fmt.Fprintf(progress, "Connecting with: %s\n", dest)
	h, err := probe(ctx, dest, target.HostPublicKey, seeds, cmd.Bool("accept-host-key"))
	if err != nil {
		return err
	}

	grants := map[string][]string{}
	created := false
	if target.ID == "" && !dryRun {
		target.HostPublicKey = h.HostKey
		if target, err = c.CreateTarget(ctx, target, cmd.StringSlice("tag"), seeds); err != nil {
			return err
		}
		created = true
		fmt.Fprintf(progress, "Added target %s\n", ui.Bold(target.Name))
	}
	if target.ID != "" {
		if grants, err = c.TargetPrincipals(ctx, target); err != nil {
			return err
		}
	}
	plan := manual.NewPlan(strings.Join(ca.TrustedKeys(), "\n"), grants, h)

	if !dryRun {
		if err = applyPlan(ctx, c, target, created, dest, h, plan, progress); err != nil {
			return err
		}
	}
	if asJSON {
		return printJSON(newSyncResult(target, plan, seeds, dryRun))
	}
	if dryRun {
		printPlan(plan, seeds)
	}
	return nil
}

// probe stops when the host key changed, or when a grant names an account the host does not have.
func probe(
	ctx context.Context,
	dest remote,
	pinnedKey string,
	seeds []client.Grant,
	acceptKey bool,
) (manual.Host, error) {
	out, err := dest.run(ctx, "sh -s", manual.ProbeCommand)
	if err != nil {
		return manual.Host{}, err
	}
	h, err := manual.ParseProbe(out)
	if err != nil {
		return h, fmt.Errorf("%s: %w", dest.host, err)
	}
	if err = checkHostKey(pinnedKey, h.HostKey, dest.host, acceptKey); err != nil {
		return h, err
	}
	for _, g := range seeds {
		if !slices.Contains(h.Accounts, g.Account) {
			return h, fmt.Errorf(
				"%s has no login account %s, nothing was written. It has: %s",
				dest.host, g.Account, strings.Join(h.Accounts, ", "),
			)
		}
	}
	return h, nil
}

// checkHostKey stops a sync that would hand a changed host key to every user.
func checkHostKey(pinned, seen, host string, accept bool) error {
	if pinned == "" || pinned == seen {
		return nil
	}
	if !accept {
		return fmt.Errorf(
			"the host key of %s changed since the last sync, nothing was written. "+
				"If the server was reinstalled, run again with --accept-host-key to pin the new one",
			host,
		)
	}
	warnf("the host key of %s changed since the last sync, users will trust the new one", host)
	return nil
}

// A new target has no principals yet, so a file a grant will fill names its subjects as typed.
func printPlan(plan manual.Plan, seeds []client.Grant) {
	fmt.Println("Dry run, nothing was written. This sync would write:")
	for _, f := range plan.Files {
		empty := ui.Dim("(empty, nobody may log in)\n")
		for _, g := range seeds {
			if g.Account == path.Base(f.Path) {
				empty = ui.Dim("(the principals of " + strings.Join(g.Subjects, ", ") + ")\n")
			}
		}
		fmt.Printf("\n%s\n%s", ui.Bold(f.Path), cmp.Or(f.Content, empty))
	}
	for _, path := range plan.Stale {
		fmt.Printf("\n%s %s\n", ui.Bold("remove"), path)
	}
}

type syncResult struct {
	Target  string        `json:"target"`
	DryRun  bool          `json:"dry_run"`
	Files   []manual.File `json:"files"`
	Removed []string      `json:"removed"`
	// Grants are the subjects a new target starts with, as they were typed.
	Grants map[string][]string `json:"grants,omitempty"`
}

func newSyncResult(target *state.Target, plan manual.Plan, seeds []client.Grant, dryRun bool) syncResult {
	res := syncResult{
		Target:  target.Name,
		DryRun:  dryRun,
		Files:   plan.Files,
		Removed: append([]string{}, plan.Stale...),
	}
	for _, g := range seeds {
		if res.Grants == nil {
			res.Grants = map[string][]string{}
		}
		res.Grants[g.Account] = g.Subjects
	}
	return res
}

// applyPlan writes the host first and reports to Nokku only once that worked.
func applyPlan(
	ctx context.Context,
	c *client.Client,
	target *state.Target,
	created bool,
	dest remote,
	h manual.Host,
	plan manual.Plan,
	progress io.Writer,
) error {
	out, err := dest.run(ctx, "sh -s", plan.Script())
	fmt.Fprint(progress, ui.Dim(ui.Plain(manual.Output(out))))
	if err != nil {
		if !created {
			return fmt.Errorf("writing to %s failed, nothing was reported to Nokku: %w", dest.host, err)
		}
		// A new target exists before its host is written, so a failed write takes it back. Also after Ctrl-C.
		if delErr := c.DeleteTarget(context.WithoutCancel(ctx), target); delErr != nil {
			return fmt.Errorf("writing to %s failed and the new target %s is still in Nokku, "+
				"remove it with nk rm %s --keep-host: %w", dest.host, target.Name, target.Name, errors.Join(err, delErr))
		}
		return fmt.Errorf("writing to %s failed, the new target %s was removed again: %w", dest.host, target.Name, err)
	}
	if err = c.ReportTarget(ctx, target, h.Accounts, h.HostKey); err != nil {
		return fmt.Errorf("the host is up to date, but reporting to Nokku failed, run nk sync again: %w", err)
	}

	res := manual.ParseResult(out)
	if !res.Reloaded {
		warnf("could not reload sshd, restart it on the host to apply the changes")
	}
	if !res.Verified {
		warnf("sshd is not using the Nokku drop-in. Make sure /etc/ssh/sshd_config has\n" +
			"  Include /etc/ssh/sshd_config.d/*.conf\nnear the top, then run nk sync again")
	}

	// Refresh locally so nk ls, ssh_config, and the host key pin match at once.
	if err = c.SyncOrCache(ctx, false); err != nil {
		warnf("local refresh failed, run nk login to update your ssh config")
	}
	fmt.Fprintf(
		progress,
		"%s %s is synced. Users connect with: ssh <user>@%s\n",
		ui.Green("✔"), target.Name, target.Name,
	)
	return nil
}

func rmCMD() *cli.Command {
	return &cli.Command{
		Name:  "rm",
		Usage: "Remove a server you added with nk sync",
		Description: "Connects as root with your own ssh, removes the Nokku CA, the sshd drop-in, " +
			"and the principals files, then deletes the target in Nokku.",
		ArgsUsage: "<host | root@host | target-name>",
		Flags: []cli.Flag{
			portFlag,
			&cli.BoolFlag{Name: "keep-host", Usage: "Delete the target only and leave the server as it is"},
			&cli.BoolFlag{
				Name:  "accept-host-key",
				Usage: "Go on when the host key changed since the last sync",
			},
		},
		Action: targetDelete,
	}
}

// The host is cleaned first, so a target never disappears from Nokku while its server still trusts the CA.
func targetDelete(ctx context.Context, cmd *cli.Command) error {
	host, err := rootHost(cmd)
	if err != nil {
		return err
	}

	c, err := connect(ctx, cmd)
	if err != nil {
		return err
	}
	target, dest, err := findRemoteTarget(ctx, c, remote{host: host, port: cmd.String("port")})
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("no target matches %s, check the name in the Nokku web app", host)
	}

	if !cmd.Bool("keep-host") {
		if dest, err = dest.trust(target, cmd.Bool("accept-host-key")); err != nil {
			return err
		}
		defer dest.close(ctx)
		fmt.Printf("Connecting with: %s\n", dest)
		// The address may lead to another machine by now, which must keep its own config.
		if _, err = probe(ctx, dest, target.HostPublicKey, nil, cmd.Bool("accept-host-key")); err != nil {
			return err
		}
		out, runErr := dest.run(ctx, "sh -s", manual.RemoveScript)
		fmt.Print(ui.Dim(ui.Plain(manual.Output(out))))
		if runErr != nil {
			return fmt.Errorf(
				"cleaning up %s failed, the target was not deleted. Pass --keep-host to delete it anyway: %w",
				dest.host, runErr,
			)
		}
		if !manual.ParseResult(out).Reloaded {
			warnf("could not reload sshd, restart it on the host to apply the changes")
		}
	}

	if err = c.DeleteTarget(ctx, target); err != nil {
		return fmt.Errorf("deleting %s in Nokku failed, run it again with --keep-host: %w", target.Name, err)
	}
	if err = c.SyncOrCache(ctx, false); err != nil {
		warnf("local refresh failed, run nk login to update your ssh config")
	}
	fmt.Printf("%s %s is deleted\n", ui.Green("✔"), target.Name)
	return nil
}

func rootHost(cmd *cli.Command) (string, error) {
	arg := cmd.Args().First()
	if arg == "" {
		return "", fmt.Errorf("which server? For example: %s 10.0.0.5", cmd.FullName())
	}
	user, host, found := strings.Cut(arg, "@")
	if found && user != "root" {
		return "", fmt.Errorf("%s connects as root, use root@%s", cmd.FullName(), host)
	}
	if !found {
		host = arg
	}
	return host, nil
}

// findRemoteTarget also returns where to connect. The access snapshot misses targets the operator may not log in to.
func findRemoteTarget(ctx context.Context, c *client.Client, dest remote) (*state.Target, remote, error) {
	targets, err := c.ListAllTargets(ctx)
	if err != nil {
		return nil, dest, fmt.Errorf("listing targets: %w", err)
	}
	aliases := ssh.HostAliases(c.State)
	target, at, err := findTarget(targets, aliases, dest)
	if target != nil || err != nil {
		return target, at, err
	}
	// An ssh alias never matches a stored address, so resolve it, but keep connecting through the alias.
	target, _, err = findTarget(targets, aliases, dest.resolve(ctx))
	return target, dest, err
}

// A name or an nk ls alias wins over an address. A name is reached at its first endpoint.
func findTarget(targets []state.Target, aliases map[string]string, dest remote) (*state.Target, remote, error) {
	type match struct {
		t  *state.Target
		at remote
	}
	var named, reached []match
	for i := range targets {
		t := &targets[i]
		if t.Name == dest.host || aliases[t.ID] == dest.host {
			at := dest
			if len(t.Endpoints) > 0 {
				at = endpointRemote(t.Endpoints[0], dest.port)
			}
			named = append(named, match{t, at})
		} else if at, ok := endpointMatch(t, dest); ok {
			reached = append(reached, match{t, at})
		}
	}
	matches := named
	if len(matches) == 0 {
		matches = reached
	}
	switch {
	case len(matches) == 0:
		return nil, dest, nil
	case len(matches) > 1:
		return nil, dest, fmt.Errorf("%s matches several targets, pass the target name or --port", dest.host)
	case !matches[0].t.Manual():
		return nil, dest, fmt.Errorf(
			"%s runs the Nokku daemon, this command is for servers without it", matches[0].t.Name,
		)
	}
	return matches[0].t, matches[0].at, nil
}

// endpointMatch compares the port only when dest knows one. An endpoint without a port is on 22.
func endpointMatch(t *state.Target, dest remote) (remote, bool) {
	for _, ep := range t.Endpoints {
		r := endpointRemote(ep, "")
		if r.host == dest.host && (dest.port == "" || cmp.Or(r.port, "22") == dest.port) {
			return remote{host: r.host, port: cmp.Or(dest.port, r.port)}, true
		}
	}
	return remote{}, false
}

// targetCA falls back to the core, the access snapshot only has the CAs of targets the operator may log in to.
func targetCA(ctx context.Context, c *client.Client, id string) (*state.CA, error) {
	if ca := c.State.CAByID(id); ca != nil {
		return ca, nil
	}
	cas, err := c.ListSSHCAs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing certificate authorities: %w", err)
	}
	if i := slices.IndexFunc(cas, func(ca state.CA) bool { return ca.ID == id }); i >= 0 {
		return &cas[i], nil
	}
	return nil, nil //nolint:nilnil // the caller names the missing CA
}

// Created on the core only once the host key is read. The local state only knows the CAs of existing targets.
func newTarget(
	ctx context.Context,
	c *client.Client,
	cmd *cli.Command,
	dest remote,
) (*state.Target, *state.CA, error) {
	cas, err := c.ListSSHCAs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("listing certificate authorities: %w", err)
	}
	ca, err := resolveCA(cas, cmd.String("ca"))
	if err != nil {
		return nil, nil, err
	}
	// Users dial the endpoint directly, so store the real address behind an ssh config alias.
	addr := dest.resolve(ctx)
	endpoint := addr.host
	if addr.port != "" && addr.port != "22" {
		endpoint = net.JoinHostPort(addr.host, addr.port)
	}
	return &state.Target{
		CAID:      ca.ID,
		Name:      strings.TrimSpace(cmd.String("name")),
		Endpoints: []string{endpoint},
	}, &ca, nil
}

// An id wins, then an exact name, then one that matches without case. A name that fits several CAs is refused.
func resolveCA(cas []state.CA, ref string) (state.CA, error) {
	if ref == "" {
		if i := slices.IndexFunc(cas, func(ca state.CA) bool { return ca.Default }); i >= 0 {
			return cas[i], nil
		}
		switch len(cas) {
		case 0:
			return state.CA{}, errors.New("there is no certificate authority yet, create one in the Nokku UI")
		case 1:
			return cas[0], nil
		}
		return state.CA{}, errors.New("there are several certificate authorities, pass --ca")
	}

	var exact, folded []state.CA
	for _, ca := range cas {
		switch {
		case ca.ID == ref:
			return ca, nil
		case ca.Name == ref:
			exact = append(exact, ca)
		case strings.EqualFold(ca.Name, ref):
			folded = append(folded, ca)
		}
	}
	found := exact
	if len(found) == 0 {
		found = folded
	}
	switch len(found) {
	case 0:
		return state.CA{}, fmt.Errorf("certificate authority %q not found", ref)
	case 1:
		return found[0], nil
	}
	return state.CA{}, fmt.Errorf("several certificate authorities are named %q, pass the id", ref)
}

// endpointRemote uses the endpoint's own port unless --port was set.
func endpointRemote(ep, port string) remote {
	r := remote{host: ep, port: port}
	if h, p, err := net.SplitHostPort(ep); err == nil {
		r.host = h
		r.port = cmp.Or(port, p)
	}
	return r
}

// Runs as root with the system ssh, so the operator's own keys, agent and config apply.
type remote struct {
	host string
	port string
	// dir holds the pinned known_hosts and the socket of the shared connection, for one run only.
	dir    string
	opts   []string
	pinned bool
}

func (r remote) String() string {
	if r.port == "" || r.port == "22" {
		return "ssh root@" + r.host
	}
	return "ssh -p " + r.port + " root@" + r.host
}

// portArgs leaves the port to the operator's ssh config unless one was given.
func (r remote) portArgs() []string {
	if r.port == "" {
		return nil
	}
	return []string{"-p", r.port}
}

// Asks ssh where an alias from the operator's config points, without connecting.
func (r remote) resolve(ctx context.Context) remote {
	//nolint:gosec // argv, not a shell, and -- ends the options
	out, err := exec.CommandContext(ctx, "ssh", append(r.portArgs(), "-G", "--", r.host)...).Output()
	if err != nil {
		return r
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		switch k, v, _ := strings.Cut(strings.TrimSpace(line), " "); k {
		case "hostname":
			r.host = v
		case "port":
			r.port = v
		}
	}
	return r
}

// trust decides how this run checks the host. ssh accepts nothing but a pinned key, accept takes what the host
// shows, and a new target is left to the operator's own known_hosts. close ends it.
func (r remote) trust(target *state.Target, accept bool) (remote, error) {
	dir, err := os.MkdirTemp("", "nk-sync-")
	if err != nil {
		return r, err
	}
	r.dir = dir
	knownHosts := filepath.Join(dir, "known_hosts")
	switch {
	case target.ID == "" || target.HostPublicKey == "":
	case accept:
		r.opts = ssh.AcceptHostOptions(target, knownHosts)
	default:
		if r.opts, err = ssh.PinnedHostOptions(target, knownHosts); err != nil {
			_ = os.RemoveAll(dir)
			return r, err
		}
		r.pinned = true
	}
	return r, nil
}

// close ends the shared connection, which would otherwise outlive nk for ControlPersist.
func (r remote) close(ctx context.Context) {
	if r.dir == "" {
		return
	}
	if runtime.GOOS != "windows" {
		exitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		//nolint:gosec // argv, not a shell, and -- ends the options
		_ = exec.CommandContext(exitCtx, "ssh", "-o", r.controlPath(), "-O", "exit", "--", r.host).Run()
	}
	_ = os.RemoveAll(r.dir)
}

// A socket of this run only. A master from another run checked its host its own way and is never reused.
func (r remote) controlPath() string {
	return `ControlPath="` + filepath.Join(r.dir, "cm") + `"`
}

func (r remote) run(ctx context.Context, command, stdin string) (string, error) {
	args := append(r.portArgs(), "-l", "root")
	args = append(args, r.opts...)
	if runtime.GOOS != "windows" && r.dir != "" {
		// Share one connection, so a password or key prompt comes only once.
		args = append(args, "-o", "ControlMaster=auto", "-o", r.controlPath(), "-o", "ControlPersist=30s")
	}
	// -- keeps a host that starts with - from being read as a flag.
	args = append(args, "--", r.host, command)

	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stderr = plainWriter{os.Stderr}
	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok && ee.ExitCode() == 255 {
		if r.pinned {
			return out.String(), fmt.Errorf("could not connect as root, check that this works: %s. "+
				"If ssh refused the host key because the server was reinstalled, run again with --accept-host-key", r)
		}
		return out.String(), fmt.Errorf("could not connect as root, check that this works: %s", r)
	}
	return out.String(), err
}

// plainWriter keeps escape sequences from the remote host off the terminal.
type plainWriter struct{ w io.Writer }

func (p plainWriter) Write(b []byte) (int, error) {
	if _, err := io.WriteString(p.w, ui.Plain(string(b))); err != nil {
		return 0, err
	}
	return len(b), nil
}
