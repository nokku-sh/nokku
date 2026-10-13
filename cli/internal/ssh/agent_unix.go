//go:build !windows

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/nokku-sh/nokku/cli/internal/paths"
)

// lockedListener holds the agent lock for as long as it listens.
type lockedListener struct {
	net.Listener

	lock *os.File
}

func (l lockedListener) Close() error {
	err := l.Listener.Close()
	_ = l.lock.Close()
	return err
}

func listenAgent(ctx context.Context) (net.Listener, error) {
	path := paths.AgentSocket()
	// One agent owns the socket. Without the lock two agents starting at once
	// both treat it as stale, and the loser unlinks the winner's on exit.
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("another agent owns the socket: %w", err)
	}
	// Nobody holds the lock, so an existing socket file is stale.
	if err = os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		_ = lock.Close()
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	// The config dir is 0700 already, this keeps the socket private if it is not.
	if err = os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = lock.Close()
		return nil, err
	}
	return lockedListener{Listener: ln, lock: lock}, nil
}

func dialAgent(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", paths.AgentSocket())
}

// detach starts the agent in its own session, so the SIGHUP ssh sends its
// ProxyCommand on exit never reaches it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
