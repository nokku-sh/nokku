package sysutil

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The list is sorted before truncating, so only the tail can ever change between syncs.
const maxReportedUsers = 200

func SystemUsers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "getent", "passwd")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("list system users", "error", err)
		return nil
	}

	var users []string
	for line := range bytes.SplitSeq(output, []byte("\n")) {
		if len(line) == 0 {
			continue
		}

		parts := strings.Split(string(line), ":")
		if len(parts) != 7 {
			continue
		}

		uid, parseErr := strconv.Atoi(parts[2])
		if parseErr != nil {
			continue
		}

		if isValidSSHUser(uid, parts[6]) {
			users = append(users, parts[0])
		}
	}
	return capUsers(users)
}

func capUsers(users []string) []string {
	slices.Sort(users)
	if len(users) > maxReportedUsers {
		return users[:maxReportedUsers]
	}
	return users
}

func isValidSSHUser(uid int, shell string) bool {
	isHumanOrRoot := uid == 0 || uid >= 1000
	hasValidShell := !strings.HasSuffix(shell, "nologin") &&
		!strings.HasSuffix(shell, "false") &&
		!strings.HasSuffix(shell, "sync")

	return isHumanOrRoot && hasValidShell
}
