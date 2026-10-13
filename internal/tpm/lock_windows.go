//go:build windows

package tpm

import (
	"os"

	"golang.org/x/sys/windows"
)

// flock blocks until f is locked exclusively. Closing f releases it.
func flock(f *os.File) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		1,
		0,
		new(windows.Overlapped),
	)
}
