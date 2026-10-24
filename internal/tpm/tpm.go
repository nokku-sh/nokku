package tpm

import (
	"fmt"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Available reports whether a TPM 2.0 device can be opened on this machine.
// The error carries the reason (missing device, permission denied, ...).
func Available() error {
	dev, err := openTPMDevice()
	if err != nil {
		return err
	}
	return dev.Close()
}

// createTPMKey makes a P-256 key inside the TPM, under the owner's storage root key. The TPM hands out the private
// half only wrapped to itself, so the blob is useless on any other TPM, and every state file holds its own key.
func createTPMKey(dev transport.TPMCloser) (*keyfile.TPMKey, error) {
	key, err := keyfile.NewLoadableKey(dev, tpm2.TPMAlgECC, 256, nil, keyfile.WithDescription("nokku"))
	if err != nil {
		return nil, fmt.Errorf("create tpm key: %w", err)
	}
	return key, nil
}
