//go:build windows

package id

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

func machineID() (string, error) {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return "", nil
	}
	defer k.Close()

	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil || guid == "" {
		return "", nil
	}

	return strings.ToLower(guid), nil
}
