package sysutil

import (
	"errors"
	"os"
)

func IsRoot() error {
	if os.Geteuid() == 0 {
		return nil
	}
	return errors.New(
		"the embedded SSH server must run as root so sessions can be dropped to the target user's privileges",
	)
}
