package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/mizuchilabs/kata/sigx"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/nokku-sh/nokku/daemon/internal/client"
	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
	"github.com/nokku-sh/nokku/daemon/internal/sysutil"
	"github.com/nokku-sh/nokku/internal/nktoken"
	"github.com/nokku-sh/nokku/internal/tpm"
	"github.com/nokku-sh/nokku/internal/trust"
)

const (
	// Docker kills a container 10 s after stop, so shutdown must fit in stopGrace.
	stopGrace       = 9 * time.Second
	unenrollTimeout = 2 * time.Second

	// A restart waits this long for sessions, so a fix can't wait on them forever.
	upgradeWait = time.Hour
	upgradeTick = 5 * time.Second
)

var (
	// errNotEnrolled exits with EX_CONFIG, which the unit file does not restart.
	errNotEnrolled = cli.Exit("nokkud: this host is not enrolled, run: sudo nokkud enroll", 78)
	// errRestart exits with EX_TEMPFAIL, which the unit file restarts.
	errRestart = cli.Exit("nokkud: restarting for the new binary", 75)
)

func main() {
	cmd := &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nokkud",
		Usage:                 "zero-trust SSH access",
		Description: `nokkud enrolls this server with Nokku and runs an embedded SSH server beside
the host sshd (on :4022 by default) that authenticates users via short-lived
SSH certificates. The host sshd on port 22 is never touched.`,
		Version: buildinfo.String(),
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logx.Init(cmd.Bool("debug"))
			return ctx, nil
		},
		Action: run,
		Commands: []*cli.Command{
			{
				Name:   "sftp-server",
				Usage:  "Serve the SFTP protocol over stdin/stdout (spawned by the embedded SSH server)",
				Hidden: true,
				Action: helper,
			},
			{
				Name:   "forward",
				Usage:  "Open the socket of a port forward as the session user (spawned by the embedded SSH server)",
				Hidden: true,
				Action: helper,
			},
			{
				Name:   "signal",
				Usage:  "Signal a session's process as the session user (spawned by the embedded SSH server)",
				Hidden: true,
				Action: helper,
			},
			{
				Name:  "enroll",
				Usage: "Enroll this host with Nokku, then exit",
				Description: `Prompts for the enrollment token from the Nokku web app, or reads
NOKKUD_ENROLL_TOKEN for unattended installs. The token never goes on the command line.
A Nokku with a certificate from a private CA is trusted through NOKKUD_CA_FILE.
Run it again to move the host to another Nokku. Restart the service afterwards.

The service enrolls itself on start when NOKKUD_ENROLL_TOKEN is set and nothing is
enrolled yet, which is how a container joins. Once enrolled, the variable is ignored.`,
				Action: enroll,
			},
			{
				Name:        "reset",
				Usage:       "Cleanup application state and delete this daemon",
				Description: `Cleans up all local certificates, principal caches, and enrollment data. Use this to decommission this machine or before re-enrolling.`,
				Action:      reset,
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "debug",
				Usage:   "Enable debug logging",
				Sources: cli.EnvVars("NOKKUD_DEBUG"),
			},
			&cli.BoolFlag{
				Name:    "require-tpm",
				Usage:   "Require a TPM 2.0 for request signing, refuse the software fallback key",
				Sources: cli.EnvVars("NOKKUD_REQUIRE_TPM"),
			},
			&cli.StringFlag{
				Name:    "ssh-addr",
				Usage:   "listen address for the embedded SSH server",
				Value:   ":4022",
				Sources: cli.EnvVars("NOKKUD_SSH_ADDR"),
			},
			&cli.StringFlag{
				Name:    "api",
				Usage:   "Nokku API URL, https only",
				Sources: cli.EnvVars("NOKKUD_API_URL"),
			},
			&cli.StringFlag{
				Name:    "ca-file",
				Usage:   "PEM file with the private CA of the Nokku API",
				Sources: cli.EnvVars("NOKKUD_CA_FILE"),
			},
		},
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}

func helper(ctx context.Context, cmd *cli.Command) error {
	return sshd.RunHelper(ctx, cmd.Name, cmd.Args().Slice())
}

func run(ctx context.Context, cmd *cli.Command) error {
	if err := sysutil.IsRoot(); err != nil {
		return err
	}
	// Never stopped, USR1 would kill us by default.
	upgraded := make(chan os.Signal, 1)
	signal.Notify(upgraded, syscall.SIGUSR1)

	st, err := loadState(cmd)
	if err != nil {
		return err
	}
	// Only an unenrolled host reads it, so a leftover token can't move a host.
	token := ""
	if st.DaemonID == "" {
		if token = os.Getenv("NOKKUD_ENROLL_TOKEN"); token == "" {
			return errNotEnrolled
		}
	}
	cl, err := enrollHost(ctx, cmd, token, st)
	if err != nil {
		return err
	}

	// Serving and uploads stop with ctx, so a client exit must cancel it too.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The grace counts from here, cl.Run first waits for relayed sessions.
	stopped := make(chan time.Time, 1)
	context.AfterFunc(ctx, func() { stopped <- time.Now() })
	uploads := cl.StartUploads(ctx)
	srv, err := sshd.New(uploads)
	if err != nil {
		return err
	}
	srv.SetAccess(st.Access())
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", cmd.String("ssh-addr"))
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cmd.String("ssh-addr"), err)
	}
	slog.Info("starting nokkud", "version", buildinfo.Version, "ssh_addr", l.Addr())

	var wg sync.WaitGroup
	wg.Go(func() { srv.Serve(ctx, l) })
	var restart atomic.Bool
	wg.Go(func() {
		if awaitIdle(ctx, upgraded, srv.Idle) {
			restart.Store(true)
			cancel()
		}
	})
	addr, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		return err
	}
	err = cl.Run(ctx, srv, addr)
	cancel()
	uploadsBy := (<-stopped).Add(stopGrace - unenrollTimeout)
	// Serve returns once every session ended, so all recordings are closed.
	wg.Wait()
	uploaded := uploads.Wait(time.Until(uploadsBy))
	if !uploaded {
		slog.Warn("recordings still uploading at shutdown, the next start sends them")
	}
	// Before the unenroll below, a host that restarts comes back.
	if restart.Load() {
		return errRestart
	}
	// An ephemeral host never comes back, so it deletes its own record. With
	// recordings left it keeps its files, and the core retires it later.
	if err == nil && uploaded && st.Access().DaemonConfig.GetEphemeral() {
		unenroll(context.WithoutCancel(ctx), cl)
	}
	return err
}

// awaitIdle takes an upgrade's USR1, then waits for the last connection to end.
// The upgrade may run in one of them, a restart right away would hang it up.
// False means ctx ended first.
func awaitIdle(ctx context.Context, upgraded <-chan os.Signal, idle func() bool) bool {
	select {
	case <-ctx.Done():
		return false
	case <-upgraded:
	}
	slog.Info("new binary installed, restarting once the last session ends", "at_most", upgradeWait)
	deadline := time.After(upgradeWait)
	ticker := time.NewTicker(upgradeTick)
	defer ticker.Stop()
	for !idle() {
		select {
		case <-ctx.Done():
			return false
		case <-deadline:
			slog.Warn("sessions outlasted the wait, ending them to restart")
			return true
		case <-ticker.C:
		}
	}
	slog.Info("the last session ended, restarting")
	return true
}

// The local state always goes, or a broken identity could never be reset.
func unenroll(ctx context.Context, cl *client.Client) {
	defer paths.Cleanup()
	ctx, cancel := context.WithTimeout(ctx, unenrollTimeout)
	defer cancel()
	if err := cl.Unenroll(ctx); err != nil {
		slog.Warn("delete daemon from core failed, local state removed", "error", err)
	}
}

func enroll(ctx context.Context, cmd *cli.Command) error {
	if err := sysutil.IsRoot(); err != nil {
		return err
	}
	st, err := loadState(cmd)
	if err != nil {
		return err
	}
	token, err := enrollToken()
	if err != nil {
		return err
	}
	if _, err = enrollHost(ctx, cmd, token, st); err != nil {
		return err
	}
	fmt.Println("Enrolled. Start the daemon with: sudo systemctl restart nokkud")
	return nil
}

// enrollHost builds the client, enrolling first when a token is given.
func enrollHost(ctx context.Context, cmd *cli.Command, token string, st *state.State) (*client.Client, error) {
	if token != "" {
		if err := checkEnrollToken(token); err != nil {
			return nil, err
		}
	}
	cl, err := newDaemonClient(ctx, cmd, token, st)
	if trust.Untrusted(err) {
		return nil, fmt.Errorf(
			"this machine does not trust the certificate of %s. If it comes from a private CA, "+
				"point NOKKUD_CA_FILE at that CA: %w",
			st.APIURL,
			err,
		)
	}
	if err == nil && token != "" {
		warnHomeKeys(ctx)
	}
	return cl, err
}

// Port 22 is the way back in, so it is never changed, only flagged.
func warnHomeKeys(ctx context.Context) {
	files := sysutil.SSHDHomeKeyFiles(ctx)
	if len(files) == 0 {
		return
	}
	slog.Warn("sshd reads keys from home directories, so a user granted an account here "+
		"can add one and keep logging in on port 22 after a revoke",
		"files", files, "fix", "https://github.com/nokku-sh/nokku/blob/main/daemon/SECURITY.md#your-own-sshd")
}

func reset(ctx context.Context, cmd *cli.Command) error {
	if err := sysutil.IsRoot(); err != nil {
		return err
	}
	st, err := loadState(cmd)
	if err != nil {
		slog.Warn("load local state, removing it anyway", "error", err)
		paths.Cleanup()
		return nil
	}
	cl, err := newDaemonClient(ctx, cmd, "", st)
	if err != nil {
		slog.Warn("delete daemon from core failed, local state removed", "error", err)
		paths.Cleanup()
		return nil
	}
	unenroll(ctx, cl)
	return nil
}

// The API URL and CA persist with the enrollment. Flags win only when given.
func loadState(cmd *cli.Command) (*state.State, error) {
	if err := paths.Verify(); err != nil {
		return nil, err
	}
	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	if api := strings.TrimRight(cmd.String("api"), "/"); cmd.IsSet("api") && api != st.APIURL {
		// The CA of one Nokku is never trusted for another.
		st.APIURL, st.APICA = api, ""
	}
	if st.APIURL == "" {
		st.APIURL = state.DefaultAPIURL
	}
	if err = checkAPIURL(st.APIURL); err != nil {
		return nil, err
	}
	if path := cmd.String("ca-file"); path != "" {
		// #nosec G304 -- the operator names the file
		ca, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("CA file: %w", readErr)
		}
		if err = trust.CheckBundle(ca); err != nil {
			return nil, fmt.Errorf("CA file %s: %w", path, err)
		}
		st.APICA = string(ca)
	}
	return st, st.Save()
}

// A sync carries the trusted CA, so plain http would let a MITM log in as root.
func checkAPIURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("API URL: %w", err)
	}
	ip, _ := netip.ParseAddr(u.Hostname())
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && (u.Hostname() == "localhost" || ip.IsLoopback()):
		return nil
	}
	return fmt.Errorf("the API URL %q must use https, plain http is only accepted for localhost", raw)
}

func checkEnrollToken(token string) error {
	if !nktoken.Valid(token, nktoken.KindEnroll) {
		return errors.New("this is not a whole enrollment token, those start with nk_" + nktoken.KindEnroll + "_. " +
			"A token of the older format no longer works, create a new one in the web app")
	}
	return nil
}

// Tokens never go on argv, where any local user could read them.
func enrollToken() (string, error) {
	if token := os.Getenv("NOKKUD_ENROLL_TOKEN"); token != "" {
		return token, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no enrollment token: set NOKKUD_ENROLL_TOKEN or run on a terminal")
	}
	fmt.Fprint(os.Stderr, "Enrollment token: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read enrollment token: %w", err)
	}
	return strings.TrimSpace(string(secret)), nil
}

func newDaemonClient(ctx context.Context, cmd *cli.Command, token string, st *state.State) (*client.Client, error) {
	cl, err := client.New(ctx, st, cmd.Bool("require-tpm"), token)
	if errors.Is(err, tpm.ErrIdentityChanged) {
		return nil, fmt.Errorf(
			"the daemon signing key no longer matches this machine, re-enroll with `sudo nokkud enroll`: %w",
			err,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("initialize daemon client: %w", err)
	}
	return cl, nil
}
