package tpm

import (
	"fmt"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func Available() error {
	dev, err := openTPMDevice()
	if err != nil {
		return err
	}
	return dev.Close()
}

// The private half only leaves wrapped to this TPM, useless on any other.
func createTPMKey(dev transport.TPMCloser) (*keyfile.TPMKey, error) {
	key, err := keyfile.NewLoadableKey(dev, tpm2.TPMAlgECC, 256, nil, keyfile.WithDescription("nokku"))
	if err != nil {
		return nil, fmt.Errorf("create tpm key: %w", err)
	}
	return key, nil
}
