package email

import (
	"errors"

	emailverifier "github.com/AfterShip/email-verifier"
)

var (
	ErrInvalidAddress = errors.New("invalid email address")
	ErrNoMailDomain   = errors.New("email domain does not accept mail")
)

// verifier never updates its bundled list, so it works air-gapped.
var verifier = emailverifier.NewVerifier()

// Verify with strict rejects disposable and MX-less domains. Self-hosted
// installs may have no DNS, so they skip it.
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
