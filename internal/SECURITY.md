# Security of the shared packages

These packages hold the crypto `nk` and `nokkud` share, and `dpop`, `login`
and `nktoken` ship in the core too. A flaw here affects every binary that
uses them. The [README](./README.md) describes the machine identity trust
model.

Found a vulnerability? Don't open a public issue. See
[SECURITY.md](../SECURITY.md) for how to report it.

## Scope

In scope:

- `dpop`: DPoP proof signing, claims and the embedded JWK, and the verifier
  the core runs: nonces, the htu compare, the token hash and the replay check.
- `dpopclient`: the DPoP interceptors, nonce learning, the binding of proofs
  to the configured API URL, the retry on a stale nonce, and the TLS 1.3
  HTTP/2 transport.
- `login`: the principal formats a certificate carries, the sshd rule
  `nk sync` writes, the account name rule and the passwd parser.
- `nktoken`: the format and checksum of every token the core hands out.
- `trust`: loading a private CA from a file, and the verification that
  follows.
- `id`: the machine fingerprint and how it hides the raw machine ID.
- `tpm`: TPM-backed and software-fallback signing identities, key wrapping,
  the persisted state format, and identity change detection.

Out of scope:

- The core, `nokkud` and `nk` themselves, which have their own files, except
  where the issue is in how they call these packages.
- A process on the same machine that can read a state file and open the TPM
  device. The README's trust model covers why the key has no auth value. `nk`
  limits what such a process gets, see "What a compromised machine can do" in
  [cli/SECURITY.md](../cli/SECURITY.md).
- Reading the software fallback key file on the machine it belongs to. The
  wrap only stops a copied file from working elsewhere.
- Vulnerabilities in the TPM hardware, firmware, or go-tpm itself.
