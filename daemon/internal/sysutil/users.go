package sysutil

import (
	"context"
	"log/slog"
	"os/exec"
	"time"

	"github.com/nokku-sh/nokku/internal/login"
)

func SystemUsers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "getent", "passwd").Output()
	if err != nil {
		slog.Warn("list system users", "error", err)
		return nil
	}
	return login.Accounts(string(output))
}
