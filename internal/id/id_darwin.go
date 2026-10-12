//go:build darwin

package id

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

func machineID() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.SplitSeq(string(out), "\n")
	for line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, `"`)
			if len(parts) >= 4 {
				return parts[3], nil
			}
		}
	}
	return "", errors.New("could not parse macOS ioreg output")
}
