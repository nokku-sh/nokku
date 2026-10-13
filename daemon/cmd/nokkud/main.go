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
	"strings"
	"sync"
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
	"github.com/nokku-sh/nokku/internal/tpm"
	"github.com/nokku-sh/nokku/internal/trust"
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
				Action: func(_ context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return errors.New("usage: nokkud sftp-server")
					}
					return sshd.ServeSFTP()
				},
			},
			{
				Name:  "enroll",
				Usage: "Enroll this host with Nokku, then exit",
				Description: `Prompts for the enrollment token from the Nokku web app, or reads
NOKKUD_ENROLL_TOKEN for unattended installs. The token never goes on the command line.
A Nokku with a private certificate is trusted through NOKKUD_API_PIN, which the
enroll command in the web app carries, or through NOKKUD_CA_FILE.
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
				Name:    "api-pin",
				Usage:   "Pin of the private CA of the Nokku API, read at enroll",
				Sources: cli.EnvVars("NOKKUD_API_PIN"),
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

// errNotEnrolled exits with EX_CONFIG, which the unit file does not restart.
var errNotEnrolled = cli.Exit("nokkud: this host is not enrolled, run: sudo nokkud enroll", 78)

// unenrollTimeout fits in Docker's default stop grace period.
const unenrollTimeout = 8 * time.Second

func run(ctx context.Context, cmd *cli.Command) error {
	if err := sysutil.IsRoot(); err != nil {
		return err
	}
	cache, cfg, err := loadState(cmd)
	if err != nil {
		return err
	}
	// Only an unenrolled host reads the variable, so a persistent one cannot re-enroll or move a host.
	token := ""
	if cfg.DaemonID == "" {
		if token = os.Getenv("NOKKUD_ENROLL_TOKEN"); token == "" {
			return errNotEnrolled
		}
	}
	cl, err := enrollHost(ctx, cmd, token, cache, cfg)
	if err != nil {
		return err
	}

	srv, err := sshd.New(sshd.Options{
		Principals:    cache.CertPrincipals,
		Policy:        sshd.PolicyFrom(cache.DaemonConfig()),
		RecordingSink: cl.RecordingSink,
	})
	if err != nil {
		return err
	}
	srv.SetTrust(cache.CAs())
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", cmd.String("ssh-addr"))
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cmd.String("ssh-addr"), err)
	}
	slog.Info("starting nokkud", "version", buildinfo.Version, "ssh_addr", l.Addr())

	// Serve stops with ctx, so a client exit (rejection) must cancel it too.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() { srv.Serve(ctx, l) })
	addr, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		return err
	}
	err = cl.Run(ctx, srv, addr)
	cancel()
	wg.Wait()
	// An ephemeral host is gone for good once it stops, so it takes its record with it.
	if err == nil && cache.DaemonConfig().GetEphemeral() {
		unenroll(context.WithoutCancel(ctx), cl)
	}
	return err
}

// unenroll deletes the daemon from the core and wipes the local state. It has to fit in a container's
// stop grace period, and the local state goes regardless, or a broken identity could never be reset.
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
	cache, cfg, err := loadState(cmd)
	if err != nil {
		return err
	}
	token, err := enrollToken()
	if err != nil {
		return err
	}
	if _, err = enrollHost(ctx, cmd, token, cache, cfg); err != nil {
		return err
	}
	fmt.Println("Enrolled. Start the daemon with: sudo systemctl restart nokkud")
	return nil
}

// enrollHost builds the client, enrolling first when a token is given. The pin of a private CA is fetched
// before, so the enroll call already trusts the core.
func enrollHost(
	ctx context.Context,
	cmd *cli.Command,
	token string,
	cache *state.Cache,
	cfg *state.Config,
) (*client.Client, error) {
	if pin := cmd.String("api-pin"); token != "" && pin != "" {
		ca, err := trust.Bootstrap(ctx, cfg.APIURL, pin)
		if err != nil {
			return nil, err
		}
		cfg.APICA = string(ca)
		if err = cfg.Save(); err != nil {
			return nil, err
		}
	}
	cl, err := newDaemonClient(ctx, cmd, token, cache, cfg)
	if trust.Untrusted(err) {
		return nil, fmt.Errorf(
			"this machine does not trust the certificate of %s. Copy the enroll command from the Nokku web app, "+
				"it carries NOKKUD_API_PIN, or point NOKKUD_CA_FILE at the CA: %w",
			cfg.APIURL,
			err,
		)
	}
	return cl, err
}

func reset(ctx context.Context, cmd *cli.Command) error {
	if err := sysutil.IsRoot(); err != nil {
		return err
	}
	cache, cfg, err := loadState(cmd)
	if err != nil {
		slog.Warn("load local state, removing it anyway", "error", err)
		paths.Cleanup()
		return nil
	}
	cl, err := newDaemonClient(ctx, cmd, "", cache, cfg)
	if err != nil {
		slog.Warn("delete daemon from core failed, local state removed", "error", err)
		paths.Cleanup()
		return nil
	}
	unenroll(ctx, cl)
	return nil
}

// The API URL and its CA are bound to the enrollment, so they are persisted and flags only win when given.
func loadState(cmd *cli.Command) (*state.Cache, *state.Config, error) {
	if err := paths.Verify(); err != nil {
		return nil, nil, err
	}
	cache := state.NewCache()
	if err := cache.Load(); err != nil {
		return nil, nil, err
	}
	cfg := new(state.Config)
	if err := cfg.Load(); err != nil {
		return nil, nil, err
	}
	if api := strings.TrimRight(cmd.String("api"), "/"); cmd.IsSet("api") && api != cfg.APIURL {
		// The CA of one Nokku is never trusted for another.
		cfg.APIURL, cfg.APICA = api, ""
	}
	if cfg.APIURL == "" {
		cfg.APIURL = state.DefaultAPIURL
	}
	if err := checkAPIURL(cfg.APIURL); err != nil {
		return nil, nil, err
	}
	if path := cmd.String("ca-file"); path != "" {
		ca, err := os.ReadFile(path) // #nosec G304 -- the operator names the file
		if err != nil {
			return nil, nil, fmt.Errorf("CA file: %w", err)
		}
		if _, err = trust.ParseBundle(ca); err != nil {
			return nil, nil, fmt.Errorf("CA file %s: %w", path, err)
		}
		cfg.APICA = string(ca)
	}
	return cache, cfg, cfg.Save()
}

// A sync answer carries the CA the daemon trusts, so plain http would let anyone in transit log in as root.
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

func newDaemonClient(
	ctx context.Context,
	cmd *cli.Command,
	token string,
	cache *state.Cache,
	cfg *state.Config,
) (*client.Client, error) {
	cl, err := client.New(ctx, cache, cfg, cmd.Bool("require-tpm"), token)
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
