//go:build !windows

package client

import (
	"context"
	"os/exec"
	"runtime"
)

// openBrowser hands url to the desktop's opener and waits for it to return.
func openBrowser(ctx context.Context, url string) error {
	openers := []string{"xdg-open", "x-www-browser", "www-browser"}
	if runtime.GOOS == "darwin" {
		openers = []string{"open"}
	}
	for _, opener := range openers {
		if path, err := exec.LookPath(opener); err == nil {
			// Stdout and Stderr stay nil, which is the null device. A writer would wait on the browser.
			return exec.CommandContext(ctx, path, url).Run()
		}
	}
	return exec.ErrNotFound
}
