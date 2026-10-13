package iam

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound   = errors.New("iam: not found")
	ErrEmailTaken = errors.New("iam: email already taken")
	// errInvalidCredentials never says which part was wrong.
	errInvalidCredentials = errors.New("iam: invalid credentials")
	ErrInactive           = errors.New("iam: account inactive")
	ErrOwner              = errors.New("iam: the owner cannot be removed, transfer ownership first")
	ErrSeatLimit          = errors.New("iam: seat limit reached")
	ErrInviteSpent        = errors.New("iam: invitation is no longer valid")
	ErrLastCredential     = errors.New("iam: the last way to sign in stays")
	ErrManagedAccount     = errors.New("iam: an identity provider manages this account")
	ErrInvalidToken       = errors.New("iam: invalid token")
	ErrEmailRejected      = errors.New("iam: email rejected")
	ErrMailNotSent        = errors.New("iam: mail not sent")
	ErrSSORequired        = errors.New("iam: single sign-on is required for this workspace")
	ErrSecretRequired     = errors.New("iam: a new issuer needs the client secret again")
	errNoSession          = errors.New("iam: no session token")
	errSessionExpired     = errors.New("iam: session expired")
	errIdentityLinked     = errors.New("iam: identity already linked to another account")
	errIdentityRejected   = errors.New("iam: identity rejected")
	errEmailUnverified    = errors.New("iam: the provider has not verified the email")
	errOwnerLink          = errors.New("iam: the owner links an identity while signed in")
	// ErrDPoPRequired is advertised with a DPoP-Nonce header so the client signs and retries (RFC 9449 section 8).
	ErrDPoPRequired    = errors.New("iam: dpop proof required")
	errInvalidProof    = errors.New("iam: invalid dpop proof")
	ErrDPoPNonce       = errors.New("iam: dpop nonce required")
	errReplay          = fmt.Errorf("%w: replayed proof", errInvalidProof)
	errBindingMismatch = fmt.Errorf("%w: jkt mismatch", errInvalidProof)
)

// IsCredentialError tells a refused credential from a failure to check one. Only the first may end a session.
func IsCredentialError(err error) bool {
	for _, target := range []error{
		errNoSession, errSessionExpired, errInvalidCredentials, ErrInactive, ErrNotFound,
		ErrDPoPRequired, ErrDPoPNonce, errInvalidProof,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
