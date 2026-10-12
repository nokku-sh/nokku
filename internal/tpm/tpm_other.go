//go:build !linux && !windows

package tpm

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

func openTPMDevice() (transport.TPMCloser, error) {
	return nil, errors.New("TPM signing is not supported on this platform")
}
