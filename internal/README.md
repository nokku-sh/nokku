# Shared packages

Go packages the daemon (`nokkud`) and the CLI (`nk`) share. They hold the
security primitives both need so they cannot drift apart: both keep their
identities in the same machine TPM, so the crypto that does this must have
exactly one implementation. The core does not use them.

## Packages

- **dpop** - client-side DPoP (RFC 9449) proof signing. Signs compact
  `dpop+jwt` proofs with an ECDSA P-256 signer, embedding the public JWK so
  the server can bind a session to the key thumbprint without pre-registration.
- **dpopclient** - the DPoP-authenticated connect client stack (interceptors,
  nonce learning, one retry on a stale nonce) and the HTTP/2-only TLS 1.3
  transport both binaries share. It always verifies the server and never
  follows a redirect. Proofs bind to the configured API URL and nothing else,
  so a client has to reach the server by the name in `NOKKU_BASE_URL`. A
  server that says it lives at another URL is refused with
  `ErrAPIURLMismatch`, which names the URL to use.
- **trust** - trust in a server whose certificate comes from a private CA.
  The client fetches the CA the server advertises at `/ca.crt`, keeps it only
  when it matches a pin it got out of band, and verifies the usual way from
  then on. There is no way to skip verification.
- **id** - stable machine fingerprint from the hardware machine ID, HMAC'd so
  the raw identifier is never exposed. The hostname stands in only on a
  machine that has no ID or a placeholder one. An ID that cannot be read is
  an error, never a guess. Used only as the software signing key's wrap
  password.
- **tpm** - machine-bound ECDSA P-256 signing identities. `Signer` is a
  persisted identity, TPM-backed when a TPM 2.0 is usable with a
  machine-wrapped software fallback otherwise. `NewSigner` loads or creates
  it, and every `SignerOptions.StatePath` is an identity of its own.
  `SignerOptions.Enclave` plugs in another hardware key store, such as the
  macOS Secure Enclave, tried after the TPM and before the software key.
  A `.lock` file beside the state file keeps two processes from creating
  different keys at once.

## Machine identity trust model

A TPM key is created inside the TPM under the owner's storage root key, in
the TSS2 key file format that `ssh-tpm-agent` and the OpenSSL TPM providers
use (via [go-tpm-keyfiles](https://github.com/foxboron/go-tpm-keyfiles)).
The TPM only hands out the private half wrapped to itself, and that blob is
kept in the 0600 state file. Using the key takes both: the blob and access
to the TPM device. The blob loads on no other TPM, and a TPM clear makes it
unloadable, which `NewSigner` reports as `ErrIdentityChanged`. Every state
file holds a random key of its own, so another user on the machine, or
another binary, cannot rebuild it from the TPM alone.

The key has no auth value and no PCR policy. A stored auth value would have
to live beside the blob and adds nothing, and PCR sealing breaks on kernel
and firmware updates. The file permissions on the state file are the
boundary on the machine.

An enclave identity (`SignerOptions.Enclave`) works the same way: its opaque
key blob is kept in the state file and only opens on the machine that
created it, with no auth value. Any process that can read the state file as
the owning user can ask the enclave to sign. A new enclave or TPM key must
sign a test digest before it is persisted, so a half-working key store falls
back to the software key instead of becoming an identity that cannot log in.

The software fallback wraps the key with a key derived from the machine's
public fingerprint (`id.MachineID`). That stops a key file copied to another
machine from working. It is not encryption against anyone who can read the
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
