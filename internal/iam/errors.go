package iam

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound   = errors.New("iam: not found")
	ErrEmailTaken = errors.New("iam: email already taken")
	// ErrInvalidCredentials never distinguishes unknown email from wrong password.
	ErrInvalidCredentials = errors.New("iam: invalid credentials")
	ErrInactive           = errors.New("iam: account inactive")
	ErrNoSession          = errors.New("iam: no session token")
	ErrSessionExpired     = errors.New("iam: session expired")
	ErrInvalidToken       = errors.New("iam: invalid token")
	ErrEmailUnverified    = errors.New("iam: email not verified")
	ErrEmailRejected      = errors.New("iam: email rejected")
	ErrCredentialsExpired = errors.New("iam: credentials expired")
	// ErrDPoPRequired is advertised with a DPoP-Nonce header so the client
	// signs and retries (RFC 9449 section 8).
	ErrDPoPRequired    = errors.New("iam: dpop proof required")
	ErrInvalidProof    = errors.New("iam: invalid dpop proof")
	ErrDPoPNonce       = errors.New("iam: dpop nonce required")
	ErrReplay          = fmt.Errorf("%w: replayed proof", ErrInvalidProof)
	ErrBindingMismatch = fmt.Errorf("%w: jkt mismatch", ErrInvalidProof)
)
