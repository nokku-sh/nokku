package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ecdsaSignature mirrors crypto/ecdsa's internal type for DER encoding.
type ecdsaSignature struct {
	R, S *big.Int
}

// Available reports whether a TPM 2.0 device can be opened on this machine.
// The error carries the reason (missing device, permission denied, ...).
func Available() error {
	dev, err := openTPMDevice()
	if err != nil {
		return err
	}
	return dev.Close()
}

// eccSignTemplate returns the deterministic ECC P-256 signing template. The
// key derives from the owner seed and this template, so the same public key
// returns on every boot with nothing stored, and the private key only ever
// exists inside the TPM. The salt sits in the unique field, the part of the
// template the spec reserves for telling primaries apart.
//
// No auth value and no PCR policy, so any process that can open the TPM
// device can use the identity. Control device access instead.
func eccSignTemplate(salt []byte) tpm2.TPMTPublic {
	// Hashed so a salt of any length fits a P-256 coordinate.
	unique := sha256.Sum256(salt)
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: unique[:]},
				Y: tpm2.TPM2BECCParameter{Buffer: []byte{}},
			},
		),
	}
}

// createPrimary creates the deterministic ECC P-256 primary key for salt.
// Nothing is persisted: the same salt on the same TPM reproduces the same
// key pair until the TPM's owner seed changes (TPM clear or replacement).
func createPrimary(
	r transport.TPM,
	salt []byte,
) (tpm2.TPMHandle, tpm2.TPM2BName, *ecdsa.PublicKey, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(eccSignTemplate(salt)),
	}.Execute(r)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, fmt.Errorf("create primary key: %w", err)
	}

	pub, err := publicToECDSA(rsp.OutPublic)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(r)
		return 0, tpm2.TPM2BName{}, nil, err
	}
	return rsp.ObjectHandle, rsp.Name, pub, nil
}

// signECDSA signs a SHA-256 digest with the loaded key and returns the
// DER-encoded signature.
func signECDSA(r transport.TPM, hnd tpm2.TPMHandle, name tpm2.TPM2BName, digest []byte) ([]byte, error) {
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: hnd,
			Name:   name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		// InScheme stays NULL, the key template pins the ECDSA scheme. The
		// validation ticket must be explicit, a zero ticket has Tag=0, which
		// the TPM rejects as an invalid structure tag.
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(r)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("decode tpm signature: %w", err)
	}
	return asn1MarshalECDSA(ecc.SignatureR.Buffer, ecc.SignatureS.Buffer)
}

func asn1MarshalECDSA(r, s []byte) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(r),
		S: new(big.Int).SetBytes(s),
	})
}

func publicToECDSA(pub tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	tp, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if tp.Type != tpm2.TPMAlgECC {
		return nil, errors.New("TPM key is not ECC")
	}
	point, err := tp.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("decode ECC point: %w", err)
	}
	curve := elliptic.P256()
	size := (curve.Params().BitSize + 7) / 8

	// TPM coordinates are big-endian with leading zero bytes stripped.
	// SEC 1 uncompressed form is 0x04 || X || Y with each coordinate
	// padded to the curve size.
	pad := func(b []byte) ([]byte, error) {
		if len(b) > size {
			return nil, errors.New("coordinate longer than curve size")
		}
		out := make([]byte, size)
		copy(out[size-len(b):], b)
		return out, nil
	}
	x, err := pad(point.X.Buffer)
	if err != nil {
		return nil, fmt.Errorf("parse ECC point: %w", err)
	}
	y, err := pad(point.Y.Buffer)
	if err != nil {
		return nil, fmt.Errorf("parse ECC point: %w", err)
	}

	data := make([]byte, 1+2*size)
	data[0] = 0x04
	copy(data[1:], x)
	copy(data[1+size:], y)

	key, err := ecdsa.ParseUncompressedPublicKey(curve, data)
	if err != nil {
		return nil, fmt.Errorf("parse ECC point: %w", err)
	}
	return key, nil
}
