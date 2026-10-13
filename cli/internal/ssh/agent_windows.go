//go:build windows

package ssh

import (
	"context"
	"net"
	"os/exec"
	"syscall"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/nokku-sh/nokku/cli/internal/paths"
)

// ownerOnly grants the pipe's owner full access and nobody else anything.
const ownerOnly = "D:P(A;;GA;;;OW)"

func listenAgent(context.Context) (net.Listener, error) {
	return winio.ListenPipe(paths.AgentSocket(), &winio.PipeConfig{SecurityDescriptor: ownerOnly})
}

func dialAgent(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, paths.AgentSocket())
}

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}
