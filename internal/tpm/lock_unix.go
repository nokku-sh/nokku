//go:build unix

package tpm

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// flock blocks until f is locked exclusively. Closing f releases it.
func flock(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
