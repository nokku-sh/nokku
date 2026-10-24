package dpopclient

import (
	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/tpm"
)

// NewProofer builds a DPoP proofer over an internal/tpm machine signer. The key
// lives in the state file opts names.
func NewProofer(opts tpm.SignerOptions) (*dpop.Proofer, error) {
	signer, err := tpm.NewSigner(opts)
	if err != nil {
		return nil, err
	}
	return dpop.NewProofer(signer)
}
