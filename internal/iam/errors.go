package iam

import (
	"errors"
	"fmt"
)

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
	// ErrCredentialsExpired is returned when a service-account credential is
	// past the expiry stored on its row.
	ErrCredentialsExpired = errors.New("iam: credentials expired")
	// ErrDPoPRequired marks a key-bound session token presented without a
	// DPoP proof. Like a stale nonce, it is advertised with a DPoP-Nonce
	// header so the client signs and retries (RFC 9449 section 8).
	ErrDPoPRequired = errors.New("iam: dpop proof required")
	// ErrInvalidProof marks a malformed or failing DPoP proof. Specific
	// failures wrap it so callers can match the class with [errors.Is].
	ErrInvalidProof = errors.New("iam: invalid dpop proof")
	// ErrDPoPNonce marks a proof missing or bearing a stale server nonce.
	ErrDPoPNonce = errors.New("iam: dpop nonce required")
	// ErrReplay marks a proof whose jti was already consumed (RFC 9449
	// sections 8.1 and 11.1). It wraps ErrInvalidProof.
	ErrReplay = fmt.Errorf("%w: replayed proof", ErrInvalidProof)
	// ErrBindingMismatch marks a valid proof whose key does not match the
	// session's bound thumbprint. It wraps ErrInvalidProof.
	ErrBindingMismatch = fmt.Errorf("%w: jkt mismatch", ErrInvalidProof)
)
