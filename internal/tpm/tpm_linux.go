//go:build linux

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// Not /dev/tpm0, it allows one open at once and leaks handles on a crash.
func openTPMDevice() (transport.TPMCloser, error) {
	return linuxtpm.Open("/dev/tpmrm0")
}
