//go:build linux

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// Only the resource manager device. /dev/tpm0 allows a single open at a time
// and leaks key handles when a process dies.
func openTPMDevice() (transport.TPMCloser, error) {
	return linuxtpm.Open("/dev/tpmrm0")
}
