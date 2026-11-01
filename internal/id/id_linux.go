//go:build linux

package id

import (
	"errors"
	"io/fs"
	"os"
	"strings"
)

func machineID() (string, error) {
	return readMachineID([]string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/sys/class/dmi/id/product_uuid",
	})
}

// Missing and root-only files like product_uuid are no ID. Other failures stop,
// the next source would change every wrapped key.
func readMachineID(paths []string) (string, error) {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			continue
		}
		if err != nil {
			return "", err
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
