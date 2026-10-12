//go:build freebsd || netbsd || openbsd || dragonfly || solaris

package id

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

func machineID() (string, error) {
	b, err := os.ReadFile("/etc/hostid")
	if err == nil && len(b) > 0 {
		return strings.TrimSpace(string(b)), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd, err := exec.CommandContext(ctx, "/sbin/sysctl", "-n", "kern.hostuuid").Output()
	if err == nil && len(cmd) > 0 {
		return strings.TrimSpace(string(cmd)), nil
	}
	return "", errors.New("could not find BSD machine-id")
}
