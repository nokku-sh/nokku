package sshd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The hidden nokkud commands the daemon runs itself as, with the session user's privileges.
const (
	helperSFTP    = "sftp-server"
	helperForward = "forward"
	helperSignal  = "signal"
)

const (
	forwardDial   = "dial"
	forwardListen = "listen"
	// Covers the helper's start and its dial.
	forwardTimeout = 10 * time.Second
	dialTimeout    = 5 * time.Second
	signalTimeout  = 5 * time.Second
	// A request is one packet. The helper reads more than this, so a long address is refused and never cut.
	maxForwardAddr = 512
)

// Tests swap it to re-enter the test binary.
var helperArgv = func(name string, args ...string) ([]string, error) {
	// os.Executable, not argv[0]: the child runs as the target user, so argv must never steer the binary.
	bin, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return append([]string{bin, name}, args...), nil
}

// RunHelper is the entry point of the helper commands.
func RunHelper(ctx context.Context, name string, args []string) error {
	switch {
	case name == helperSFTP && len(args) == 0:
		return serveSFTP()
	case name == helperForward && len(args) == 0:
		return serveForwardSocket(ctx)
	case name == helperSignal && len(args) == 2:
		return sendSignal(args[0], args[1])
	}
	return fmt.Errorf("bad arguments for %s", name)
}

// The kernel then checks the helper as the user, where the daemon's own syscalls would pass as root.
func helperCmd(ctx context.Context, a *account, name string, args ...string) (*exec.Cmd, error) {
	argv, err := helperArgv(name, args...)
	if err != nil {
		return nil, err
	}
	// #nosec G204 - argv is this binary.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// Never the daemon's own environment, the user could read it from /proc.
	cmd.Env = []string{"HOME=" + a.Home}
	cmd.Dir = "/"
	if cmd.SysProcAttr, err = sysProcAttr(a); err != nil {
		return nil, err
	}
	return cmd, nil
}

func shellJoin(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

func dialAs(a *account, addr string) (net.Conn, error) {
	f, err := openSocketAs(a, forwardDial, addr)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	// The helper runs as the user, who could make it hand over anything.
	if _, ok := c.(*net.TCPConn); !ok {
		_ = c.Close()
		return nil, errors.New("forward helper returned no TCP connection")
	}
	return c, nil
}

func listenAs(a *account, addr string) (net.Listener, error) {
	f, err := openSocketAs(a, forwardListen, addr)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}
	if _, ok := ln.(*net.TCPListener); !ok {
		_ = ln.Close()
		return nil, errors.New("forward helper returned no TCP listener")
	}
	return ln, nil
}

// The socket keeps the credentials of the process that made it, so owner rules in a firewall see the user.
func openSocketAs(a *account, mode, addr string) (*os.File, error) {
	if len(addr) > maxForwardAddr {
		return nil, errors.New("forward address too long")
	}
	ctx, cancel := context.WithTimeout(context.Background(), forwardTimeout)
	defer cancel()

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "forward"), os.NewFile(uintptr(pair[1]), "forward-helper")
	conn, err := net.FileConn(ours)
	_ = ours.Close()
	if err != nil {
		_ = theirs.Close()
		return nil, err
	}
	defer conn.Close()

	cmd, err := helperCmd(ctx, a, helperForward)
	if err != nil {
		_ = theirs.Close()
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{theirs}
	err = cmd.Start()
	_ = theirs.Close()
	if err != nil {
		return nil, err
	}
	// A helper that dies or is killed at the timeout closes its end, which ends the read below.
	defer func() { _ = cmd.Wait() }()

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("forward socket pair is no unix socket")
	}
	if _, err = uc.Write([]byte(mode + " " + addr)); err != nil {
		return nil, err
	}
	buf, oob := make([]byte, 1024), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fmt.Errorf("forward helper: %w", err)
	}
	if oobn == 0 {
		// No socket came back, so the packet is the helper's error.
		return nil, errors.New(cmp.Or(string(buf[:n]), "forward helper sent no answer"))
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return nil, errors.New("forward helper sent a bad control message")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return nil, errors.New("forward helper sent no socket")
	}
	return os.NewFile(uintptr(fds[0]), "forward-socket"), nil
}

// Takes one request on fd 3 and answers with the socket, or with the error as text.
func serveForwardSocket(ctx context.Context) error {
	daemon := os.NewFile(3, "daemon")
	conn, err := net.FileConn(daemon)
	_ = daemon.Close()
	if err != nil {
		return err
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("fd 3 is no unix socket")
	}

	buf := make([]byte, 2*maxForwardAddr)
	n, err := uc.Read(buf)
	if err != nil {
		return err
	}
	mode, addr, _ := strings.Cut(string(buf[:n]), " ")
	f, err := openSocket(ctx, mode, addr)
	if err != nil {
		_, _ = uc.Write([]byte(err.Error()))
		return err
	}
	defer f.Close()
	_, _, err = uc.WriteMsgUnix([]byte{0}, unix.UnixRights(int(f.Fd())), nil)
	return err
}

func openSocket(ctx context.Context, mode, addr string) (*os.File, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	switch mode {
	case forwardDial:
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if tc, ok := c.(*net.TCPConn); ok {
			return tc.File()
		}
	case forwardListen:
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		defer ln.Close()
		if tl, ok := ln.(*net.TCPListener); ok {
			return tl.File()
		}
	}
	return nil, fmt.Errorf("bad forward request %q", mode)
}

// Like sshd, the kill runs as the session user. As root it would also reach a process that became privileged,
// like a sudo the user started.
func (sess *session) signalProc(pid int, name string) {
	ctx, cancel := context.WithTimeout(sess.ctx, signalTimeout)
	defer cancel()
	cmd, err := helperCmd(ctx, sess.sysUser, helperSignal, strconv.Itoa(pid), name)
	if err == nil {
		err = cmd.Run()
	}
	if err != nil {
		slog.Debug("signal session process failed", "signal", name, "error", err)
	}
}

func sendSignal(pid, name string) error {
	p, err := strconv.Atoi(pid)
	if err != nil || p <= 0 {
		return fmt.Errorf("bad pid %q", pid)
	}
	sig, _ := signalByName(name)
	s, ok := sig.(syscall.Signal)
	if !ok {
		return fmt.Errorf("unknown signal %q", name)
	}
	return syscall.Kill(p, s)
}
