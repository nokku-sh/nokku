//go:build linux

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// Only the resource manager device, /dev/tpm0 allows one open at a time and leaks handles when a process dies.
func openTPMDevice() (transport.TPMCloser, error) {
	return linuxtpm.Open("/dev/tpmrm0")
}
