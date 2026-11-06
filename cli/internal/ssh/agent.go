package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/nokku-sh/nokku/internal/tpm"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

const (
	agentIdle         = 30 * time.Minute
	shutdownExtension = "shutdown@nokku.sh"
)

var errSignOnly = errors.New("the nk agent only signs with the Nokku identity")

// Reloads the signer on a new public key, so no agent restart is needed.
type identity struct {
	requireTPM bool
	pub        []byte
	ring       agent.ExtendedAgent
}

// Signing only. ssh-add can't add keys, remove the key or lock the agent.
type signOnly struct {
	agent.ExtendedAgent

	shutdown func()
}

// EnsureAgent starts a shared agent that outlives every ssh session.
func EnsureAgent(ctx context.Context, s *state.State) error {
	// With a security key ssh signs through the key itself.
	if s.SecurityKey || agentAlive(ctx) {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"agent"}
	if s.RequireTPM {
		args = []string{"--require-tpm", "agent"}
	}
	//nolint:noctx // the agent must outlive this ssh session
	cmd := exec.Command(exe, args...)
	cmd.Env = agentEnv()
	detach(cmd)
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("start nk agent: %w", err)
	}
	_ = cmd.Process.Release()

	for range 50 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if agentAlive(ctx) {
			return nil
		}
	}
	return errors.New("the nk agent did not start, run nk doctor")
}

// Drops NK_TOKEN, the agent never calls the core and outlives its command.
func agentEnv() []string {
	return slices.DeleteFunc(os.Environ(), func(kv string) bool {
		key, _, _ := strings.Cut(kv, "=")
		return strings.EqualFold(key, "NK_TOKEN")
	})
}

func RunAgent(ctx context.Context, requireTPM bool) error {
	if agentAlive(ctx) {
		return nil
	}
	ln, err := listenAgent(ctx)
	if err != nil {
		if agentAlive(ctx) {
			return nil // lost a start race to another agent
		}
		return fmt.Errorf("listen on agent socket: %w", err)
	}
	shutdown := func() { _ = ln.Close() }
	idle := time.AfterFunc(agentIdle, shutdown)
	stop := context.AfterFunc(ctx, shutdown)
	defer stop()

	id := identity{requireTPM: requireTPM}
	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return nil
		}
		idle.Reset(agentIdle)
		ring, keyErr := id.keyring()
		if keyErr != nil {
			slog.Error("load ssh identity", "err", keyErr)
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_ = agent.ServeAgent(signOnly{ExtendedAgent: ring, shutdown: shutdown}, conn)
		}()
	}
}

func (id *identity) keyring() (agent.ExtendedAgent, error) {
	pub, err := os.ReadFile(paths.PubKeyFile())
	if err != nil {
		return nil, err
	}
	if id.ring != nil && bytes.Equal(pub, id.pub) {
		return id.ring, nil
	}
	// A replaced signer is not closed, connections may still be using it.
	signer, err := newSSHSigner(id.requireTPM)
	if err != nil {
		return nil, err
	}
	comment := "nokku (software)"
	if signer.Method() == tpm.MethodTPM {
		comment = "nokku (tpm)"
	}
	ring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		return nil, errors.New("keyring does not support extensions")
	}
	if err = ring.Add(agent.AddedKey{PrivateKey: signer, Comment: comment}); err != nil {
		return nil, err
	}
	id.pub, id.ring = pub, ring
	return ring, nil
}

func agentAlive(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := dialAgent(ctx)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// StopAgent is best effort, an agent that misses it exits once idle.
func StopAgent(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := dialAgent(ctx)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = agent.NewClient(conn).Extension(shutdownExtension, nil)
}

func (signOnly) Add(agent.AddedKey) error         { return errSignOnly }
func (signOnly) Remove(cryptossh.PublicKey) error { return errSignOnly }
func (signOnly) RemoveAll() error                 { return errSignOnly }
func (signOnly) Lock([]byte) error                { return errSignOnly }
func (signOnly) Unlock([]byte) error              { return errSignOnly }

func (a signOnly) Extension(name string, _ []byte) ([]byte, error) {
	if name != shutdownExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	a.shutdown()
	return nil, nil
}
