# Security Policy

## Supported Versions

These packages ship inside `nokkud` and `nk`. Only the latest release of
those is supported for security fixes.

## Reporting a Vulnerability

Please **do not** open a public issue for a suspected security vulnerability.
Use GitHub's private vulnerability reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide as much of the following as you can:

   - The affected `nokkud` or `nk` release
   - A description of the issue and its security impact
   - Steps to reproduce, or a minimal patch/poc
   - Any supporting logs (redact secrets)

Reports are handled confidentially. We will acknowledge receipt, and if you
would like to be credited in the release advisory or changelog, let us know.
This is optional but appreciated.

### Response timeline

- **Acknowledge** the report: within 48 hours
- **Triage** and classify severity: within 5 business days
- **Fix / mitigation / response**: we aim to provide a fix or clear guidance
  within 30 days, depending on the complexity and impact.

## Scope

The following are in scope for security reports:

- `dpop`: DPoP proof signing, claims, and the embedded JWK.
- `dpopclient`: the DPoP interceptors, nonce and canonical-URL learning, the
  retry on a stale nonce, and the TLS 1.3 HTTP/2 transport.
- `id`: the machine fingerprint and how it hides the raw machine ID.
- `tpm`: TPM-backed and software-fallback signing identities, key wrapping,
  the persisted state format, and identity change detection.

### Out of scope

- The Nokku backend, `nokkud`, and `nk` themselves (each has its own
  policy), except where the issue is in how they call these packages.
- Access to the TPM device by a process on the same machine. The README's
  trust model covers why the identity has no auth value.
- Reading the software fallback key file on the machine it belongs to. The
  wrap only stops a copied file from working elsewhere.
- Vulnerabilities in the TPM hardware, firmware, or go-tpm itself.

## Security Notes / Threat Model

These packages hold the crypto `nokkud` and `nk` share, so a flaw here affects
both. The README describes the machine identity trust model and
the salt registry. Salts must differ per binary and purpose, or two binaries
would derive the same identity from one TPM.
