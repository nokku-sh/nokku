package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/nk/internal/client"
	"github.com/nokku-sh/nokku/nk/internal/ssh"
	"github.com/nokku-sh/nokku/nk/internal/state"
)

const (
	// proxyFreshFor is how long nk proxy trusts the cached access snapshot.
	proxyFreshFor = time.Minute
	// syncRetryAfter is how long nk under ssh leaves the backend alone after a
	// sync or a renewal failed. Without it every connection of an outage waits
	// for the timeout first.
	syncRetryAfter = 30 * time.Second
)

// proxyCMD is the ProxyCommand in the generated ssh_config. ssh runs it, users
// do not.
func proxyCMD() *cli.Command {
	return &cli.Command{
		Name:      "proxy",
		Usage:     "Proxy an SSH connection (used by ssh)",
		ArgsUsage: "<target-id> <port>",
		Hidden:    true,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "relay", Usage: "Always go through the Nokku relay"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			id, port := cmd.Args().Get(0), cmd.Args().Get(1)
			if id == "" || port == "" {
				return errors.New("usage: nk proxy <target-id> <port>")
			}
			s, err := loadState(cmd)
			if err != nil {
				return err
			}
			// Built on first use, so a fresh snapshot with a valid cert never
			// touches the TPM or the backend.
			backend := sync.OnceValues(func() (*client.Client, error) { return client.New(s) })

			// The daemon enforces revocation itself, so a young snapshot only
			// delays new grants, and fan-out over many hosts syncs once.
			stale := time.Since(s.SyncedAt) > proxyFreshFor && !s.SyncFailedWithin(syncRetryAfter)
			if stale || s.TargetByID(id) == nil {
				c, cerr := backend()
				if cerr != nil {
					return cerr
				}
				// Never open a browser under ssh, a stale session uses the cache.
				if err = c.SyncOrCache(ctx, false); err != nil {
					return err
				}
			}
			target := s.TargetByID(id)
			if target == nil {
				return errors.New("you no longer have access to this server, run nk ls to see yours")
			}
			ca := s.CAByID(target.CAID)
			if ca == nil {
				return fmt.Errorf("the certificate authority of %s is missing, run nk login", target.Name)
			}

			// nk prepare renewed the certificate before ssh read it. Signing
			// here only happens when that failed, or this sync brought a new CA
			// or an account granted after the certificate was signed.
			if !ssh.CertValid(*target, *ca, 0) {
				c, cerr := backend()
				if cerr == nil {
					cerr = c.EnsureCert(ctx, *target, *ca)
				}
				if cerr != nil {
					return fmt.Errorf("no valid certificate for %s, run nk login: %w", target.Name, cerr)
				}
				warnf("certificate for %s renewed, if ssh fails run it again", target.Name)
			} else if !ssh.CertCovers(*target) {
				// The old certificate still works for the accounts it names.
				if c, cerr := backend(); cerr == nil && c.EnsureCert(ctx, *target, *ca) == nil {
					warnf("certificate for %s renewed for a new account, if ssh fails run it again", target.Name)
				}
			}
			if err = ssh.EnsureAgent(ctx, s.RequireTPM); err != nil {
				return err
			}
			relay := func(ctx context.Context, t *state.Target) (io.ReadWriteCloser, error) {
				c, cerr := backend()
				if cerr != nil {
					return nil, cerr
				}
				return c.Relay(ctx, t)
			}
			return ssh.Proxy(ctx, target, port, relay, cmd.Bool("relay"))
		},
	}
}

// prepareCMD is the Match exec hook in the generated ssh_config. ssh runs it
// before it reads CertificateFile, so a missing or expiring certificate is
// renewed in time for this connection.
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

func renewCert(ctx context.Context, cmd *cli.Command) error {
	s, err := loadState(cmd)
	if err != nil {
		return err
	}
	target := s.TargetByID(cmd.Args().First())
	if target == nil {
		return errors.New("unknown target")
	}
	ca := s.CAByID(target.CAID)
	if ca == nil || ssh.CertFresh(*target, *ca) {
		return nil
	}
	// A certificate that still works is not worth a timeout while the
	// backend is down.
	if ssh.CertValid(*target, *ca, 0) && s.SyncFailedWithin(syncRetryAfter) {
		return nil
	}
	c, err := client.New(s)
	if err != nil {
		return err
	}
	if err = c.EnsureCert(ctx, *target, *ca); err != nil {
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
