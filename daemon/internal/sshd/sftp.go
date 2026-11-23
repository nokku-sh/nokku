package sshd

import (
	"io"
	"os"
	"os/exec"

	"github.com/pkg/sftp"
)

// Runs as the target user, so OS permissions bound what it can touch.
func serveSFTP() error {
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

func (sess *session) runSFTP() {
	argv, err := helperArgv(helperSFTP)
	if err != nil {
		sess.startFailed("sftp", err)
		return
	}
	// Like sshd, the login shell runs it, so a lock shell can refuse it.
	sess.rawCmd = shellJoin(argv)

	var stdin io.WriteCloser
	var stdout io.ReadCloser
	cmd, notice, err := sess.startInHome(sess.shellCmd, func(cmd *exec.Cmd) (err error) {
		stdin, stdout, err = sess.startPiped(cmd)
		return err
	})
	if err != nil {
		sess.startFailed("sftp", err)
		return
	}
	if notice != "" {
		_, _ = io.WriteString(sess.Stderr(), notice+"\n")
	}
	sess.relay(cmd, stdin, stdout)
}
