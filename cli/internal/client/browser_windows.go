//go:build windows

package client

import (
	"context"

	"golang.org/x/sys/windows"
)

func openBrowser(_ context.Context, url string) error {
	ptr, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, nil, ptr, nil, nil, windows.SW_SHOWNORMAL)
}
