package dpopclient

import (
	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/tpm"
)

// NewProofer builds a DPoP proofer over an internal/tpm machine signer. The salt in
// opts namespaces the derived key and must come from the registry documented
// in internal/README.md.
func NewProofer(opts tpm.SignerOptions) (*dpop.Proofer, error) {
	signer, err := tpm.NewSigner(opts)
	if err != nil {
		return nil, err
	}
	return dpop.NewProofer(signer)
}
