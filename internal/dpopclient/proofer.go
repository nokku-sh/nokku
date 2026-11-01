package dpopclient

import (
	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/tpm"
)

func NewProofer(opts tpm.SignerOptions) (*dpop.Proofer, error) {
	signer, err := tpm.NewSigner(opts)
	if err != nil {
		return nil, err
	}
	return dpop.NewProofer(signer)
}
