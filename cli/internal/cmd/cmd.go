package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/logx"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/client"
	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/cli/internal/ui"
	"github.com/nokku-sh/nokku/internal/nktoken"
	"github.com/nokku-sh/nokku/internal/trust"
)

var jsonFlag = &cli.BoolFlag{Name: "json", Usage: "Output machine-readable JSON"}

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
			requestCMD(),
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
				Usage:   "Address of your Nokku, remembered after the first use",
				Sources: cli.EnvVars("NK_API_URL"),
			},
			&cli.BoolFlag{
				Name:    "require-tpm",
				Usage:   "Refuse software keys. Keys live in a TPM 2.0, the ssh key may be on a security key instead",
				Sources: cli.EnvVars("NK_REQUIRE_TPM"),
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

// Plain http carries a session or token in the clear. Loopback is fine.
func plainHTTP(api string) bool {
	u, err := url.Parse(api)
	if err != nil || u.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())
}

// Signs in through the browser if needed, uses the cache if the core is down.
func connect(ctx context.Context, cmd *cli.Command) (*client.Client, error) {
	s, err := loadState(cmd)
	if err != nil {
		return nil, err
	}
	c, err := newClient(s)
	if err != nil {
		return nil, err
	}
	if err = c.SyncOrCache(ctx, true); err != nil {
		return nil, err
	}
	return c, nil
}

func loadState(cmd *cli.Command) (*state.State, error) {
	s := state.Load()
	// A save would write the newer file back as this version.
	if s.Version > state.ConfigVersion {
		return nil, fmt.Errorf(
			"%s is version %d, written by a newer nk, upgrade this one",
			paths.ConfigFile(),
			s.Version,
		)
	}
	s.Token = os.Getenv("NK_TOKEN")
	// Sticks, or the nk proxy ssh starts without flags would take a software key.
	s.RequireTPM = s.RequireTPM || cmd.Bool("require-tpm")

	// A cut, mistyped or old key gets a clear answer before any call.
	if s.Token != "" && !nktoken.Valid(s.Token, nktoken.KindServiceAccount) {
		return nil, errors.New("NK_TOKEN is not a whole service account key, those start with nk_" +
			nktoken.KindServiceAccount + "_. A key of the older format no longer works, create a new one")
	}
	if api := cmd.String("api"); s.APIURL != api && (s.APIURL == "" || cmd.IsSet("api")) {
		// Another server never gets this session or shows its targets. The key belongs to the machine.
		s.Config = state.Config{APIURL: api, SecurityKey: s.SecurityKey, RequireTPM: s.RequireTPM}
		s.Cache = state.Cache{}
	}
	if plainHTTP(s.APIURL) {
		return nil, fmt.Errorf("%s is not encrypted, Nokku is only reached over https", s.APIURL)
	}
	if path := cmd.String("ca-file"); path != "" {
		ca, err := os.ReadFile(path) // #nosec G304 -- the user named it
		if err != nil {
			return nil, fmt.Errorf("CA file: %w", err)
		}
		if err = trust.CheckBundle(ca); err != nil {
			return nil, fmt.Errorf("CA file %s: %w", path, err)
		}
		s.APICA = string(ca)
	}
	return s, nil
}

// nk logout uses client.New, it has no use for an ssh identity.
func newClient(s *state.State) (*client.Client, error) {
	// Every workspace has an address of its own, so there is none to fall back to.
	if s.APIURL == "" {
		return nil, errors.New("nk does not know your Nokku yet. Pass its address once, " +
			"like nk --api https://nokku.example.com login. The web app shows the full command")
	}
	if err := ssh.SetupKey(s); err != nil {
		return nil, err
	}
	return client.New(s)
}

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
