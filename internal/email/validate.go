package email

import (
	"errors"

	emailverifier "github.com/AfterShip/email-verifier"
)

var verifier = emailverifier.NewVerifier().
	EnableAutoUpdateDisposable().
	DisableSMTPCheck().
	DisableGravatarCheck().
	DisableCatchAllCheck()

func Verify(email string) error {
	res, err := verifier.Verify(email)
	if err != nil {
		return err
	}
	if !res.Syntax.Valid {
		return errors.New("invalid email address")
	}
	if res.Disposable {
		return errors.New("invalid email address")
	}
	if !res.HasMxRecords {
		return errors.New("email domain does not accept mail")
	}
	return nil
}
