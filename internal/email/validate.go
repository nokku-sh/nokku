package email

import (
	"context"
	"errors"
	"net"
	"net/mail"
	"strings"
	"time"
)

var (
	errInvalidAddress = errors.New("invalid email address")
	errNoMailDomain   = errors.New("email domain does not accept mail")
)

const mailDomainTimeout = 5 * time.Second

// Verify asks DNS only with strict, self-hosted installs may have no DNS.
func Verify(ctx context.Context, addr string, strict bool) error {
	parsed, err := mail.ParseAddress(addr)
	// ParseAddress also takes "Name <addr>", only the bare form is an account.
	if err != nil || parsed.Address != addr {
		return errInvalidAddress
	}
	if !strict {
		return nil
	}

	_, domain, _ := strings.CutLast(addr, "@")
	ctx, cancel := context.WithTimeout(ctx, mailDomainTimeout)
	defer cancel()
	mx, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err == nil && len(mx) > 0 {
		// A single "." is the null MX, the domain declares it takes no mail.
		if len(mx) == 1 && mx[0].Host == "." {
			return errNoMailDomain
		}
		return nil
	}
	// Without an MX record mail goes to the domain's address.
	if _, err := net.DefaultResolver.LookupHost(ctx, domain); err != nil {
		return errNoMailDomain
	}
	return nil
}
