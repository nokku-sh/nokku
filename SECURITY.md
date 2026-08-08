# Security Policy

## Supported Versions

Only the latest release of Nokku is supported for security fixes. Older
releases are not patched; if you are affected by a vulnerability, upgrade to
the newest tagged release. For self-hosted deployments, apply fixes by pulling
the latest release and restarting the backend.

## Reporting a Vulnerability

Please **do not** open a public issue for a suspected security vulnerability.
Use GitHub's private vulnerability reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide as much of the following as you can:

   - Affected Nokku version and deployment (self-hosted vs. SaaS, Enterprise
     vs. Community)
   - A description of the issue and its security impact
   - Steps to reproduce, or a minimal patch/poc
   - Any supporting logs (redact secrets and tokens)

Reports are handled confidentially. We will acknowledge receipt, and if you
would like to be credited in the release advisory or changelog, let us know —
this is optional but appreciated.

### Response timeline

- **Acknowledge** the report: within 48 hours
- **Triage** and classify severity: within 5 business days
- **Fix / mitigation / response**: we aim to provide a fix or clear guidance
  within 30 days, depending on the complexity and impact.

## Scope

The following are in scope for security reports:

- The Nokku **backend** (control plane) — authentication and OIDC, workspace
  and access-control authorization, SSH and X.509 certificate signing, daemon
  enrollment and synchronization, entitlement/licensing, audit logging, and
  secret management.
- The bundled **web application**, including browser authentication and
  terminal sessions.
- Support for external integrations the backend uses (email, OIDC providers,
  KMS, billing) **as they are exercised by the backend**, and the Helm
  chart / deployment configuration shipped in this repository.

### Out of scope

- The [`nk`](https://github.com/nokku-sh/nk) CLI and
  [`nokkud`](https://github.com/nokku-sh/nokkud) daemon — these have their own
  security policies in their respective repositories.
- The SSH protocol itself and vulnerabilities in OpenSSH / `sshd`.
- OS/distribution, container-runtime, and database-engine issues.
- The infrastructure that hosts the managed Nokku SaaS, or third-party
  provider outages.

## Security Notes / Threat Model

Nokku is the control plane. It holds signing keys for SSH and X.509
certificate authorities, encrypted secrets, and the enrollment / access data
that governs access to every target.

- Sensitive material (encrypted secrets, CA signing keys, OIDC credentials)
  is managed via `NOKKU_SECRET`/KMS and keyed to external key management when
  configured. Do not expose `NOKKU_SECRET`, license keys, or OIDC client
  secrets.
- Operate the backend behind a TLS-terminating reverse proxy and set
  `NOKKU_TRUSTED_PROXIES` to the exact set of proxy IPs/CIDRs whose forwarded
  client-IP headers should be honored.
- Set a strong `NOKKU_SECRET` (32 bytes) and rotate secrets by stopping the
  backend before running `rotate-secrets` to avoid encrypting data with
  different keys.
- Self-hosted instances default to the Community plan; Enterprise licensing is
  verified offline via Ed25519-signed license keys and falls back to Community
  when a key expires or is revoked. External KMS configuration is an Enterprise
  feature; Community deployments use `NOKKU_SECRET`.
- Releases are built via GoReleaser and signed/checksummed — verify downloads
  against the published checksums and signatures.
