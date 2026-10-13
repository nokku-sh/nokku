//go:build darwin && cgo && enclave

package enclave

/*
#cgo LDFLAGS: -L${SRCDIR}/build -lnkenclave -L/usr/lib/swift
#cgo LDFLAGS: -framework CryptoKit -framework Security -framework Foundation
#include <stdlib.h>
#include "enclave.h"
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/nokku-sh/nokku/internal/tpm"
)

// envEnable opts in to new enclave keys. Remove it once the enclave path has
// run on real hardware.
const envEnable = "NK_SECURE_ENCLAVE"

var enabled = os.Getenv(envEnable) == "1"

// backend implements tpm.Enclave over enclave.swift.
type backend struct {
	// create allows new keys. Existing keys always open.
	create bool
	// software keeps keys in memory instead of the enclave, for tests.
	software bool
}

// New returns the Secure Enclave backend, nil when this Mac has no enclave.
func New() tpm.Enclave {
	if !Available() {
		return nil
	}
	return backend{create: enabled}
}

// Available reports whether this Mac has a usable Secure Enclave.
func Available() bool { return C.nk_enclave_available() == 1 }

// Enabled reports whether new identities are created in the enclave.
func Enabled() bool { return enabled && Available() }

func (b backend) Create() ([]byte, error) {
	if !b.create {
		return nil, errors.New("enclave: Secure Enclave keys are experimental, set " + envEnable + "=1 to use them")
	}
	var (
		out  *C.uint8_t
		n    C.size_t
		cerr *C.char
	)
	rc := C.nk_enclave_create(b.flag(), &out, &n, &cerr)
	return result(rc, out, n, cerr)
}

func (b backend) Open(blob []byte) (crypto.Signer, error) {
	if len(blob) == 0 {
		return nil, errors.New("enclave: empty key blob")
	}
	var (
		out  *C.uint8_t
		n    C.size_t
		cerr *C.char
	)
	rc := C.nk_enclave_public(b.flag(), cbytes(blob), C.size_t(len(blob)), &out, &n, &cerr)
	raw, err := result(rc, out, n, cerr)
	if err != nil {
		return nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("enclave: parse public key: %w", err)
	}
	return &key{backend: b, blob: blob, pub: pub}, nil
}

func (b backend) flag() C.int {
	if b.software {
		return 1
	}
	return 0
}

// key signs with the private half behind blob, which never leaves the
// enclave.
type key struct {
	backend

	blob []byte
	pub  *ecdsa.PublicKey
}

func (k *key) Public() crypto.PublicKey { return k.pub }

// Sign signs a SHA-256 digest and returns the DER-encoded ECDSA signature.
func (k *key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("enclave: unsupported hash %v, the bridge signs SHA-256 digests", opts.HashFunc())
	}
	var (
		out  *C.uint8_t
		n    C.size_t
		cerr *C.char
	)
	rc := C.nk_enclave_sign(
		k.flag(),
		cbytes(k.blob), C.size_t(len(k.blob)),
		cbytes(digest), C.size_t(len(digest)),
		&out, &n, &cerr,
	)
	return result(rc, out, n, cerr)
}

func cbytes(b []byte) *C.uint8_t {
	return (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(b)))
}

// result copies what the bridge returned into Go memory and frees it.
func result(rc C.int, out *C.uint8_t, n C.size_t, cerr *C.char) ([]byte, error) {
	if rc != 0 {
		defer C.free(unsafe.Pointer(cerr))
		return nil, errors.New("enclave: " + C.GoString(cerr))
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(n)), nil
}
