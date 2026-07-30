package email

import (
	"errors"
	"strings"

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

func GetDomain(email string) (string, error) {
	_, domain, ok := strings.Cut(email, "@")
	if !ok || domain == "" {
		return "", errors.New("invalid email address")
	}
	return strings.ToLower(domain), nil
}
