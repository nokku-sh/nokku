//go:build linux

package id

import (
	"errors"
	"os"
	"strings"
)

func machineID() (string, error) {
	for _, p := range []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/sys/class/dmi/id/product_uuid",
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// Blank placeholders are rejected by the shared caller.
		id := strings.ToLower(strings.TrimSpace(string(data)))
		if id == "" {
			continue
		}
		return id, nil
	}

	return "", errors.New("machine-id not found")
}
