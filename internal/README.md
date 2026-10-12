# Shared packages

Go packages the daemon (`nokkud`) and the CLI (`nk`) share. They hold the
security primitives both need so they cannot drift apart: both derive their
identities from the same machine TPM, so the crypto that does this must have
exactly one implementation. The core does not use them.

## Packages

- **dpop** - client-side DPoP (RFC 9449) proof signing. Signs compact
  `dpop+jwt` proofs with an ECDSA P-256 signer, embedding the public JWK so
  the server can bind a session to the key thumbprint without pre-registration.
- **dpopclient** - the DPoP-authenticated connect client stack (interceptors,
  nonce and canonical-URL learning, one retry on a stale nonce) and the
  HTTP/2-only TLS 1.3 transport both binaries share. It always verifies the
  server.
- **trust** - trust in a server whose certificate comes from a private CA.
  The client fetches the CA the server advertises at `/ca.crt`, keeps it only
  when it matches a pin it got out of band, and verifies the usual way from
  then on. There is no way to skip verification.
- **id** - stable machine fingerprint from the hardware machine ID
  (hostname fallback), HMAC'd so the raw identifier is never exposed. Used
  only as the software signing key's wrap password.
- **tpm** - machine-bound ECDSA P-256 signing identities. `Signer` is a
  persisted identity, TPM-backed when a TPM 2.0 is usable with a
  machine-wrapped software fallback otherwise. `NewSigner` loads or creates
  it and `SignerOptions.Salt` namespaces the key per binary and purpose.
  `SignerOptions.Enclave` plugs in another hardware key store, such as the
  macOS Secure Enclave, tried after the TPM and before the software key.

## Salts

`tpm` is generic and knows nothing about products: every binary that uses it
defines its own salt constants and passes them to `NewSigner`. When one
machine runs several Nokku binaries, their salts must differ per purpose or
two binaries would silently derive the same identity from the same TPM. The
salt registry is therefore a convention, not code: each binary owns its
constants, and new purposes get new constants there.

The registry today:

| Salt                | Binary and purpose       |
| ------------------- | ------------------------ |
| `nokku-daemon`      | nokkud DPoP proofing key |
| `nokku-daemon-host` | nokkud host key          |
| `nokku-cli`         | nk DPoP proofing key     |
| `nokku-cli-ssh`     | nk user SSH signing key  |

Never change a registered salt. It would silently rotate every machine
identity derived from it.

## Machine identity trust model

A TPM-backed identity cannot be extracted: the private key never leaves the
device. The primary is created without an auth value or PCR policy, so any
process that can open the TPM device (`/dev/tpmrm0` on Linux) can use the
identity. Restrict the device to the owning daemon's uid. A stored auth value
would have to live beside the caller's state file and buys nothing, and PCR
sealing breaks on kernel and firmware updates.

An enclave identity (`SignerOptions.Enclave`) is not derived, so its opaque
key blob is kept in the state file. The blob only opens on the machine that
created it, and like the TPM key it carries no auth value: any process that
can read the state file as the owning user can ask the enclave to sign. A new
enclave key must sign a test digest before it is persisted, so a half-working
enclave falls back to the software key instead of becoming an identity that
cannot log in.

The software fallback wraps the key with a key derived from the machine's
public fingerprint (`id.MachineID`). That stops a key file copied to another
machine from working; it is not encryption against anyone who can read the
file on the machine itself. Leave `SignerOptions.Recreate` unset where the
identity is bound to a server-side registration, so a TPM clear or a re-image
makes the caller re-enroll instead of silently presenting a new key.

## Testing

The TPM tests run against the in-process
[go-tpm simulator](https://github.com/google/go-tpm/tree/master/tpm2/transport/simulator)
and skip when it cannot start. `tpm.SignerOptions.OpenTPM` is the seam that
injects it.

## License

Apache License 2.0
