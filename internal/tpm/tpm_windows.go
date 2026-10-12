//go:build windows

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

func openTPMDevice() (transport.TPMCloser, error) {
	return windowstpm.Open()
}
