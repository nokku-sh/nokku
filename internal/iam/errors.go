package iam

import "errors"

// Sentinel errors. Wrap with %w and match with [errors.Is]; transport layers
// map them to HTTP/gRPC status codes in one place.
var (
	// ErrNotFound is returned for unknown users, credentials, or sessions.
	ErrNotFound = errors.New("iam: not found")
	// ErrEmailTaken is returned when registering with an email that already
	// has an account.
	ErrEmailTaken = errors.New("iam: email already taken")
	// ErrInvalidCredentials is returned when a login fails. It deliberately
	// does not distinguish unknown email from wrong password.
	ErrInvalidCredentials = errors.New("iam: invalid credentials")
	// ErrInactive is returned when the account exists but is deactivated.
	ErrInactive = errors.New("iam: account inactive")
	// ErrNoSession is returned when no session token was presented.
	ErrNoSession = errors.New("iam: no session token")
	// ErrSessionExpired is returned when a session is expired or idle-timed
	// out. The dead session is pruned before the error returns.
	ErrSessionExpired = errors.New("iam: session expired")
	// ErrInvalidToken is returned when a one-time token is unknown, spent,
	// or expired.
	ErrInvalidToken = errors.New("iam: invalid token")
	// ErrEmailUnverified is returned when the credentials verify but the
	// account's email is not verified yet, so no session may be issued.
	ErrEmailUnverified = errors.New("iam: email not verified")
	// ErrEmailRejected is returned when a signup email fails validation:
	// malformed, disposable, or a domain that does not accept mail.
	ErrEmailRejected = errors.New("iam: email rejected")
)
