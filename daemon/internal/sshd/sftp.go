package sshd

import (
	"io"
	"log/slog"
	"os"
	"os/exec"

	"github.com/pkg/sftp"
)

// Tests swap it to re-enter the test binary.
var sftpServerCmd = func(home string) (*exec.Cmd, error) {
	// os.Executable, not argv[0]: the child runs as the target user, so argv must never steer the binary.
	bin, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// #nosec G204 - bin is this binary.
	cmd := exec.Command(bin, "sftp-server")
	// Never the daemon's own environment, the user could read it from /proc.
	cmd.Env = []string{"HOME=" + home}
	return cmd, nil
}

// ServeSFTP runs as the target user in its working directory, so the OS permissions bound what it can touch.
func ServeSFTP() error {
	rw := struct {
		io.Reader
		io.WriteCloser
	}{os.Stdin, os.Stdout}
	srv, err := sftp.NewServer(rw)
	if err != nil {
		return err
	}
	defer srv.Close()
	return srv.Serve()
}

func (sess *session) sftpCmd() (*exec.Cmd, error) {
	cmd, err := sftpServerCmd(sess.sysUser.Home)
	if err != nil {
		return nil, err
	}
	attr, err := sysProcAttr(sess.sysUser)
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr = attr
	cmd.Dir = sess.sysUser.Home
	return cmd, nil
}

func (sess *session) runSFTP() {
	var stdin io.WriteCloser
	var stdout io.ReadCloser
	cmd, notice, err := sess.startInHome(sess.sftpCmd, func(cmd *exec.Cmd) (err error) {
		stdin, stdout, err = startPiped(cmd)
		return err
	})
	if err != nil {
		slog.Debug("start sftp failed", "error", err)
		sess.exit(1)
		return
	}
	if notice != "" {
		_, _ = io.WriteString(sess.Stderr(), notice+"\n")
	}
	sess.relay(cmd, stdin, stdout)
}
