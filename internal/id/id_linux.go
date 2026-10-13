//go:build linux

package id

import (
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
		// A placeholder in one source does not rule out a real ID in the next.
		id := strings.ToLower(strings.TrimSpace(string(data)))
		if isBlankMachineID(id) {
			continue
		}
		return id, nil
	}

	return "", nil
}
