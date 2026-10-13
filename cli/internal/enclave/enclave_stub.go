//go:build !(darwin && cgo && enclave)

// Package enclave keeps nk's identities in the macOS Secure Enclave. The
// bridge is Swift linked through cgo, built only for darwin with the enclave
// tag after internal/enclave/build.sh ran. Every other build gets this stub
// and falls back to the TPM or the software key.
package enclave

import "github.com/nokku-sh/nokku/internal/tpm"

// New returns the Secure Enclave backend, nil in a build without one.
func New() tpm.Enclave { return nil }

// Available reports whether this Mac has a usable Secure Enclave.
func Available() bool { return false }

// Enabled reports whether new identities are created in the enclave.
func Enabled() bool { return false }
