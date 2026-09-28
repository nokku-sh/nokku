package email

import (
	"errors"

	emailverifier "github.com/AfterShip/email-verifier"
)

var (
	ErrInvalidAddress = errors.New("invalid email address")
	ErrNoMailDomain   = errors.New("email domain does not accept mail")
)

// verifier uses the disposable domain list bundled with the library. It never
// updates it over the network, so it works air-gapped.
var verifier = emailverifier.NewVerifier()

// Verify checks an address before signup. strict adds the checks a public
// SaaS needs: no disposable domains, and a domain with MX records. Self-hosted
// installs skip them since they may have no DNS or internet access.
func Verify(addr string, strict bool) error {
	syntax := verifier.ParseAddress(addr)
	if !syntax.Valid {
		return ErrInvalidAddress
	}
	if !strict {
		return nil
	}
	if verifier.IsDisposable(syntax.Domain) {
		return ErrInvalidAddress
	}
	if mx, err := verifier.CheckMX(syntax.Domain); err != nil || !mx.HasMXRecord {
		return ErrNoMailDomain
	}
	return nil
}
