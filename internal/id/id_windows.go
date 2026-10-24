//go:build windows

package id

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// A missing MachineGuid is no ID. Any other failure is an error, the hostname would change every wrapped key.
func machineID() (string, error) {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer k.Close()

	guid, _, err := k.GetStringValue("MachineGuid")
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return strings.ToLower(guid), nil
}
