//go:build !(darwin && cgo && enclave)

// Package enclave is the macOS Secure Enclave bridge. A build without the enclave tag gets this stub.
package enclave

import "github.com/nokku-sh/nokku/internal/tpm"

// New returns nil in a build without the enclave.
func New() tpm.Enclave { return nil }

func Available() bool { return false }

func Enabled() bool { return false }
