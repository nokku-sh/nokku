//go:build windows

package client

import (
	"os"

	"golang.org/x/sys/windows"
)

func openBrowser(url string) error {
	ptr, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, nil, ptr, nil, nil, windows.SW_SHOWNORMAL)
}

// hasBrowser is false over ssh, where the browser would open on another desktop.
func hasBrowser() bool {
	return os.Getenv("SSH_CONNECTION") == ""
}
