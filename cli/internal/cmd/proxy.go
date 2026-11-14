package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	connectrpc "connectrpc.com/connect/v2"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/client"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

const (
	// Long enough that a fan-out of ssh runs syncs once.
	proxyFreshFor = time.Minute
	// Backoff after a failed sync, or every ssh would wait for the timeout.
	syncRetryAfter = 30 * time.Second
)

func proxyCMD() *cli.Command {
	return &cli.Command{
		Name:      "proxy",
		Usage:     "Proxy an SSH connection (used by ssh)",
		ArgsUsage: "<server-id> <port>",
		Hidden:    true,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "relay", Usage: "Always go through the Nokku relay"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			id, port := cmd.Args().Get(0), cmd.Args().Get(1)
			if id == "" || port == "" {
				return errors.New("usage: nk proxy <server-id> <port>")
			}
			s, err := loadState(cmd)
			if err != nil {
				return err
			}
			// Lazy, a fresh snapshot and valid cert skip the TPM and the core.
			core := sync.OnceValues(func() (*client.Client, error) { return newClient(s) })

			// The daemon enforces revocation, staleness only delays grants.
			stale := time.Since(s.SyncedAt) > proxyFreshFor && !s.SyncFailedWithin(syncRetryAfter)
			if stale || s.TargetByID(id) == nil {
				c, cerr := core()
				if cerr != nil {
					return cerr
				}
				// No browser under ssh, a stale session uses the cache.
				if err = c.SyncOrCache(ctx, false); err != nil {
					return err
				}
			}
			target := s.TargetByID(id)
			if target == nil {
				return errors.New("you no longer have access to this server, run nk ls to see yours")
			}
			if s.CA == nil {
				return fmt.Errorf("the certificate authority of %s is missing, run nk login", target.Name)
			}

			// nk prepare failed, or this sync brought a new CA key or account.
			if !ssh.CertValid(*target, *s.CA, 0) {
				c, cerr := core()
				if cerr == nil {
					cerr = c.EnsureCert(ctx, *target, *s.CA)
				}
				if cerr != nil {
					return noCertificate(target.Name, cerr)
				}
				warnf("certificate for %s renewed, if ssh fails run it again", target.Name)
			} else if !ssh.CertCovers(*target) && !target.Behind(*s.CA) {
				// The old certificate still works for the accounts it names.
				if c, cerr := core(); cerr == nil && c.EnsureCert(ctx, *target, *s.CA) == nil {
					warnf("certificate for %s renewed for a new account, if ssh fails run it again", target.Name)
				}
			}
			if err = ssh.EnsureAgent(ctx, s); err != nil {
				return err
			}
			relay := func(ctx context.Context, t *state.Target) (io.ReadWriteCloser, error) {
				c, cerr := core()
				if cerr != nil {
					return nil, cerr
				}
				return c.Relay(ctx, t)
			}
			return ssh.Proxy(ctx, target, port, relay, cmd.Bool("relay"))
		},
	}
}

func prepareCMD() *cli.Command {
	return &cli.Command{
		Name:      "prepare",
		Usage:     "Renew the certificate for a target (used by ssh)",
		ArgsUsage: "<target-id>",
		Hidden:    true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// nk proxy runs right after and reports anything that went wrong.
			if err := renewCert(ctx, cmd); err != nil {
				slog.Debug("renew certificate before ssh", "err", err)
			}
			return nil
		},
	}
}

// nk login can't work while the core is out of reach.
func noCertificate(target string, err error) error {
	if connectrpc.CodeOf(err) == connectrpc.CodeUnavailable {
		return fmt.Errorf("no valid certificate for %s, and the core can't be reached to get one: %w", target, err)
	}
	if errors.Is(err, client.ErrCISessionEnded) {
		return fmt.Errorf("no valid certificate for %s: %w", target, err)
	}
	return fmt.Errorf("no valid certificate for %s, run nk login: %w", target, err)
}

func renewCert(ctx context.Context, cmd *cli.Command) error {
	s, err := loadState(cmd)
	if err != nil {
		return err
	}
	target := s.TargetByID(cmd.Args().First())
	if target == nil {
		return errors.New("unknown server")
	}
	if s.CA == nil || ssh.CertFresh(*target, *s.CA) {
		return nil
	}
	// A working certificate is not worth a timeout while the core is down.
	if ssh.CertValid(*target, *s.CA, 0) && s.SyncFailedWithin(syncRetryAfter) {
		return nil
	}
	c, err := newClient(s)
	if err != nil {
		return err
	}
	if err = c.EnsureCert(ctx, *target, *s.CA); err != nil {
		s.MarkSyncFailed()
	}
	return err
}

func agentCMD() *cli.Command {
	return &cli.Command{
		Name:   "agent",
		Usage:  "Serve the machine SSH identity (started by nk proxy)",
		Hidden: true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return ssh.RunAgent(ctx, cmd.Bool("require-tpm"))
		},
	}
}
