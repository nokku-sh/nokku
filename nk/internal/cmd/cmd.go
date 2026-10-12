// Package cmd defines the nk command tree.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/internal/trust"
	"github.com/nokku-sh/nokku/nk/internal/client"
	"github.com/nokku-sh/nokku/nk/internal/paths"
	"github.com/nokku-sh/nokku/nk/internal/state"
	"github.com/nokku-sh/nokku/nk/internal/ui"
)

// saPrefix marks service-account tokens. Unlike device sessions they
// authenticate with a plain Bearer header, without DPoP binding.
const saPrefix = "nk_sa_"

var jsonFlag = &cli.BoolFlag{Name: "json", Usage: "Output machine-readable JSON"}

// Root is the nk command with its global flags and every subcommand.
func Root() *cli.Command {
	return &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nk",
		Usage:                 "secure access, simplified",
		Version:               buildinfo.String(),
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logx.Init(cmd.Bool("debug"))
			if err := paths.EnsureDirs(); err != nil {
				return nil, err
			}
			return ctx, nil
		},
		Commands: []*cli.Command{
			loginCMD(),
			logoutCMD(),
			listCMD(),
			syncCMD(),
			rmCMD(),
			doctorCMD(),
			proxyCMD(),
			prepareCMD(),
			agentCMD(),
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "api",
				Usage:   "Nokku API URL",
				Value:   "https://app.nokku.sh",
				Sources: cli.EnvVars("NK_API_URL"),
			},
			&cli.DurationFlag{
				Name:    "ttl",
				Usage:   "Certificate TTL",
				Sources: cli.EnvVars("NK_TTL"),
			},
			&cli.BoolFlag{
				Name:    "require-tpm",
				Usage:   "Require a TPM 2.0 or the Secure Enclave and refuse the software key fallback",
				Sources: cli.EnvVars("NK_REQUIRE_TPM"),
			},
			&cli.StringFlag{
				Name:    "pin",
				Usage:   "Fingerprint of the server's private CA (sha256:...) from the web app. Without it nk asks",
				Sources: cli.EnvVars("NK_API_PIN"),
			},
			&cli.StringFlag{
				Name:    "ca-file",
				Usage:   "PEM file with the private CA of the Nokku API",
				Sources: cli.EnvVars("NK_CA_FILE"),
			},
			&cli.BoolFlag{
				Name:    "debug",
				Usage:   "Enable debug logging",
				Sources: cli.EnvVars("NK_DEBUG"),
			},
		},
	}
}

// loadState loads the persisted state and applies the global flags.
func loadState(cmd *cli.Command) (*state.State, error) {
	s := state.Load()
	s.Token = os.Getenv("NK_TOKEN")
	s.TTL = cmd.Duration("ttl")
	s.RequireTPM = cmd.Bool("require-tpm")
	s.Pin = cmd.String("pin")

	if s.Token != "" && !strings.HasPrefix(s.Token, saPrefix) {
		return nil, errors.New("NK_TOKEN must be a service account token starting with " + saPrefix)
	}
	if api := cmd.String("api"); s.APIURL != api && (s.APIURL == "" || cmd.IsSet("api")) {
		// Another server never gets this session or shows its targets.
		s.Config = state.Config{APIURL: api}
		s.Cache = state.Cache{}
	}
	if plainHTTP(s.APIURL) {
		return nil, fmt.Errorf("%s is not encrypted, Nokku is only reached over https", s.APIURL)
	}
	if path := cmd.String("ca-file"); path != "" {
		ca, err := os.ReadFile(path) // #nosec G304 -- the user names the file
		if err != nil {
			return nil, fmt.Errorf("CA file: %w", err)
		}
		if _, err = trust.ParseBundle(ca); err != nil {
			return nil, fmt.Errorf("CA file %s: %w", path, err)
		}
		s.APICA = string(ca)
	}
	return s, nil
}

// plainHTTP reports whether api would carry the session or a service account
// token over the network in the clear. This machine itself is fine.
func plainHTTP(api string) bool {
	u, err := url.Parse(api)
	if err != nil || u.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())
}

// connect syncs access just in time, signing in through the browser when
// needed, and falls back to the cached snapshot when the backend is
// unreachable.
func connect(ctx context.Context, cmd *cli.Command) (*client.Client, error) {
	s, err := loadState(cmd)
	if err != nil {
		return nil, err
	}
	c, err := client.New(s)
	if err != nil {
		return nil, err
	}
	if err = c.SyncOrCache(ctx, true); err != nil {
		return nil, err
	}
	return c, nil
}

// warnf prints a highlighted warning to stderr.
func warnf(format string, args ...any) {
	fmt.Fprintln(os.Stderr, ui.Yellow("warning: "+fmt.Sprintf(format, args...)))
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
