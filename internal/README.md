# Shared packages

Go packages the daemon (`nokkud`) and the CLI (`nk`) share, and the few the
core shares with them. They hold the security primitives and the contracts
all sides need so they cannot drift apart: both binaries keep their
identities in the same machine TPM, so the crypto that does this must have
exactly one implementation. The core uses `dpop`, `login` and `nktoken` only.

## Packages

- **dpop** - DPoP (RFC 9449) proofs, signed and verified. `Proofer` signs
  compact `dpop+jwt` proofs with an ECDSA P-256 signer, embedding the public
  JWK so the server can bind a session to the key thumbprint without
  pre-registration. `Verifier` is the core's side: stateless HMAC nonces,
  the htm, htu and ath checks, and a replay store the caller passes in.
  `SameURL` is the one htu compare both sides use.
- **login** - what the core, `nokkud` and `nk` agree on about a login: the
  principal formats a certificate carries, the sshd rule `nk sync` writes for
  them, the key id prefix of a web terminal certificate, `ValidUsername`,
  and the passwd parser that picks the accounts a server reports.
- **nktoken** - the format of every token the core hands out, `nk_<kind>_`
  then a random part from `rand.Text` and a checksum. The core makes and checks them with it,
  `nk` and `nokkud` check a pasted key before they send it.
- **dpopclient** - the DPoP-authenticated connect client stack (interceptors,
  nonce learning, one retry on a stale nonce) and the HTTP/2-only TLS 1.3
  transport both binaries share. It always verifies the server and never
  follows a redirect. Proofs bind to the configured API URL and nothing else,
  so a client has to reach the server by the name in `NOKKU_BASE_URL`. A
  server that says it lives at another URL is refused with
  `ErrAPIURLMismatch`, which names the URL to use.
- **trust** - trust in a server whose certificate comes from a private CA.
  The operator hands the client that CA as a PEM file, and the client
  verifies against the system roots plus that CA. There is no way to skip
  verification.
- **id** - stable machine fingerprint from the OS machine ID, or the
  hardware UUID where that is missing, HMAC'd so the raw identifier is never
  exposed. The hostname stands in only when every source is missing, a
  placeholder or unreadable for lack of permission. Any other read error
  fails, it never guesses. Used only as the software signing key's wrap
  password.
- **tpm** - machine-bound ECDSA P-256 signing identities. `Signer` is a
  persisted identity, TPM-backed when a TPM 2.0 is usable with a
  machine-wrapped software fallback otherwise. `NewSigner` loads or creates
  it, and every `SignerOptions.StatePath` is an identity of its own.
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

A new TPM key must sign a test digest before it is persisted, so a half-working
TPM falls back to the software key instead of becoming an identity that cannot
log in.

The software fallback wraps the key with a key derived from the machine's
public fingerprint (`id.MachineID`). That stops a key file copied to another
machine from working. It is not encryption against anyone who can read the
file on the machine itself. Where the identity is bound to a server-side
registration, a TPM clear or a re-image must never silently present a new key.
Leave `SignerOptions.Recreate` unset so the caller fails and re-enrolls, or set
it and treat a new public key as a new enrollment, the way `nk` signs in again
when its SSH key changes.

## Testing

The TPM tests run against the in-process
[go-tpm simulator](https://github.com/google/go-tpm/tree/master/tpm2/transport/simulator)
and skip when it cannot start. `tpm.SignerOptions.OpenTPM` is the seam that
injects it.

## License

Apache License 2.0
