package sshd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestEchoEnabled(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	ptmx, tty, err := openPTY()
	must.NoError(err)
	defer ptmx.Close()
	defer tty.Close()

	is.True(echoEnabled(ptmx))

	fd := int(tty.Fd())
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	must.NoError(err)

	noEcho := *termios
	noEcho.Lflag &^= unix.ECHO
	must.NoError(unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho))
	is.False(echoEnabled(ptmx))

	must.NoError(unix.IoctlSetTermios(fd, unix.TCSETS, termios))
	is.True(echoEnabled(ptmx))

	// A closed pty must fail closed (no leak on error).
	must.NoError(ptmx.Close())
	is.False(echoEnabled(ptmx))
}
