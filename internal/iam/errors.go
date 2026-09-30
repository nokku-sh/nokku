package iam

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound   = errors.New("iam: not found")
	ErrEmailTaken = errors.New("iam: email already taken")
	// errInvalidCredentials never distinguishes unknown email from wrong password.
	errInvalidCredentials = errors.New("iam: invalid credentials")
	ErrInactive           = errors.New("iam: account inactive")
	errNoSession          = errors.New("iam: no session token")
	errSessionExpired     = errors.New("iam: session expired")
	errInvalidToken       = errors.New("iam: invalid token")
	ErrEmailUnverified    = errors.New("iam: email not verified")
	ErrEmailRejected      = errors.New("iam: email rejected")
	errCredentialsExpired = errors.New("iam: credentials expired")
	// ErrDPoPRequired is advertised with a DPoP-Nonce header so the client
	// signs and retries (RFC 9449 section 8).
	ErrDPoPRequired    = errors.New("iam: dpop proof required")
	errInvalidProof    = errors.New("iam: invalid dpop proof")
	ErrDPoPNonce       = errors.New("iam: dpop nonce required")
	errReplay          = fmt.Errorf("%w: replayed proof", errInvalidProof)
	errBindingMismatch = fmt.Errorf("%w: jkt mismatch", errInvalidProof)
)
