package sysutil

import (
	"context"
	"os/exec"
	"time"

	"github.com/nokku-sh/nokku/internal/login"
)

// SSHDHomeKeyFiles is empty when sshd is missing or its config does not load.
func SSHDHomeKeyFiles(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sshd", "-T").Output()
	if err != nil {
		return nil
	}
	return login.HomeKeyFiles(string(out))
}
