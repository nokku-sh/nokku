//go:build !windows

package client

import (
	"os/exec"
	"runtime"
	"syscall"
)

// Started and never waited on, some openers run the browser in the foreground until it closes.
func openBrowser(url string) error {
	openers := []string{"xdg-open", "x-www-browser", "www-browser"}
	if runtime.GOOS == "darwin" {
		openers = []string{"open"}
	}
	for _, opener := range openers {
		path, err := exec.LookPath(opener)
		if err != nil {
			continue
		}
		// Stdout and Stderr stay nil, which is the null device. A writer would wait on the browser.
		cmd := exec.Command(path, url) //nolint:noctx // Ctrl-C in nk must not take the browser down
		// A process group of its own, so the terminal's Ctrl-C misses it too.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err = cmd.Start(); err != nil {
			return err
		}
		go func() { _ = cmd.Wait() }()
		return nil
	}
	return exec.ErrNotFound
}
