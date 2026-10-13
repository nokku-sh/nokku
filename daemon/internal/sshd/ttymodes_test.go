package sshd

import (
	"encoding/binary"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func encodeModes(modes ssh.TerminalModes) []byte {
	var out []byte
	for op, arg := range modes {
		out = append(out, op)
		out = binary.BigEndian.AppendUint32(out, arg)
	}
	return append(out, 0)
}

func TestParseTTYModes(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	var tio unix.Termios
	tio.Lflag = unix.ECHO | unix.ICANON
	tio.Iflag = unix.ICRNL
	tio.Cflag = unix.CS8
	parseTTYModes(&tio, encodeModes(ssh.TerminalModes{
		ssh.ECHO:   0,
		ssh.IUTF8:  1,
		ssh.ONLCR:  1,
		ssh.VERASE: 8,
		ssh.VEOF:   255,
		ssh.CS7:    1,
		ssh.CS8:    0,
	}))

	is.Zero(tio.Lflag&unix.ECHO, "ECHO cleared")
	is.NotZero(tio.Lflag&unix.ICANON, "untouched flags stay")
	is.NotZero(tio.Iflag&unix.IUTF8, "IUTF8 set")
	is.NotZero(tio.Iflag&unix.ICRNL, "untouched flags stay")
	is.NotZero(tio.Oflag&unix.ONLCR, "ONLCR set")
	is.EqualValues(8, tio.Cc[unix.VERASE], "erase character")
	is.Zero(tio.Cc[unix.VEOF], "255 disables the character")
	is.EqualValues(unix.CS7, tio.Cflag&unix.CSIZE, "a zero CS8 does not undo CS7")
}

func TestParseTTYModesStopsAtUnknownOpcode(t *testing.T) {
	t.Parallel()
	var tio unix.Termios
	modes := []byte{160, 0, 0, 0, 1, ssh.ECHO, 0, 0, 0, 1}
	parseTTYModes(&tio, modes)
	assert.Zero(t, tio.Lflag&unix.ECHO, "parsing ends at opcode 160 like sshd")

	modes = []byte{ssh.ECHO, 0, 0, 0, 1, 0, ssh.ICANON, 0, 0, 0, 1}
	parseTTYModes(&tio, modes)
	assert.NotZero(t, tio.Lflag&unix.ECHO)
	assert.Zero(t, tio.Lflag&unix.ICANON, "parsing ends at TTY_OP_END")
}

func FuzzParseTTYModes(f *testing.F) {
	f.Add(encodeModes(ssh.TerminalModes{ssh.ECHO: 0, ssh.VERASE: 127}))
	f.Add([]byte{3, 0, 0})
	f.Add([]byte{255, 1, 2, 3, 4})
	f.Fuzz(func(_ *testing.T, modes []byte) {
		var tio unix.Termios
		parseTTYModes(&tio, modes)
	})
}

// The modes a client sends in pty-req have to reach the pty, or backspace and UTF-8 handling go wrong.
func TestServerPTYModes(t *testing.T) {
	if _, err := exec.LookPath("stty"); err != nil {
		t.Skip("stty not installed")
	}
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.IUTF8: 1, ssh.VERASE: 8}
	must.NoError(sess.RequestPty("xterm", 80, 24, modes), "request pty")
	out, err := sess.Output("stty -a")
	must.NoError(err, "stty")
	flags := strings.Fields(string(out))
	is.Contains(flags, "-echo")
	is.Contains(flags, "iutf8")
	is.Contains(string(out), "erase = ^H")
}
