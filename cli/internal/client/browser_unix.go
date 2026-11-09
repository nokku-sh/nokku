//go:build !windows

package client

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// Never blocks on the opener, some run the browser until it closes.
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
		// Stdout and Stderr stay nil. A writer would wait on the browser.
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

// hasBrowser guesses if a browser here can reach nk on 127.0.0.1. Plain ssh can't.
func hasBrowser() bool {
	if os.Getenv("SSH_CONNECTION") != "" && os.Getenv("DISPLAY") == "" {
		return false
	}
	if runtime.GOOS == "darwin" || os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}
