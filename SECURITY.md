# Security

This file has two parts. The first is for reporting a vulnerability. The second is for people who run Nokku and want to do it safely.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Tell us as much of this as you can:
   - The Nokku version and how it runs (self-hosted or hosted, which plan)
   - What the issue is and what an attacker gains
   - Steps to reproduce, or a minimal proof of concept
   - Logs that help, with secrets and tokens removed

Reports are handled confidentially. If you would like credit in the advisory or the changelog, say so.

What to expect:

- **Acknowledgement** within 48 hours
- **Triage** and a severity within 5 business days
- **A fix or clear guidance** within 30 days, depending on complexity and impact

### Supported versions

Only the latest release gets security fixes. Older releases are not patched. On a self-hosted install, pull the newest release and restart the core.

### In scope

- The **core**: sign-in and OIDC, authorization, SSH and X.509 certificate signing, daemon enrollment and sync, licensing, the audit log and secret management
- The bundled **web app**, including browser sign-in and terminal sessions
- External integrations **as the core uses them** (email, OIDC providers, KMS, billing)
- The Helm chart and the deployment files in this repository

### Out of scope

- The [`nk`](https://github.com/nokku-sh/nk) CLI and the [`nokkud`](https://github.com/nokku-sh/nokkud) daemon. Each has its own policy in its repository.
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system, container runtime and database engine issues
- The infrastructure behind the hosted service, and outages of third-party providers

## Running Nokku securely

The core holds the signing keys of your SSH and X.509 certificate authorities. Whoever controls it controls access to every server. These are the settings that deserve care. Setup and the full list of settings are in the [README](./README.md).

### The secret

`NOKKU_SECRET` protects everything the core encrypts at rest: CA private keys, SSO client secrets and the keys of session recordings.

- Use at least 32 random characters, for example `openssl rand -hex 32`. The core refuses less.
- Keep it in a secret manager, never in the repository or an image.
- Back it up together with the database. One is useless without the other.
- Treat license keys and OIDC client secrets the same way.

How it works: the secrets in the database are encrypted by one keyset, which is stored in the database too. The keyset is wrapped by a key derived from `NOKKU_SECRET`, or by a KMS key when `KMS_URI` is set. Each recording is encrypted with its own key, and that key is one more secret in the database.

### Rotating the secret

Stop the core, then run the rotation with the same environment the core runs with:

```bash
NOKKU_NEW_SECRET="secret:$(cat new-secret.txt)" ./nokku rotate-secrets
```

Then set `NOKKU_SECRET` to the new value and start the core. It refuses to start with the old one.

The new secret can also be passed as `--new secret:...`. The environment variable keeps it out of the process list and your shell history.

A rotation adds a new data key to the keyset, re-encrypts the secrets in the database with it and drops the older keys, all in one transaction. The keyset never holds more than two keys. Recordings are not re-encrypted, only their keys are.

A rotation does not un-leak anything. If the old secret and an old database dump both leaked, roll over the CAs as well.

### Using a KMS

With a KMS, the key that unlocks everything lives in the KMS and not in an environment variable. This needs an Enterprise license. Community installs use `NOKKU_SECRET`.

| Variable                 | Purpose                                                                             |
| ------------------------ | ----------------------------------------------------------------------------------- |
| `KMS_URI`                | The KMS key that wraps the keyset                                                   |
| `VAULT_TOKEN`            | Token for `hcvault://`                                                              |
| `VAULT_SKIP_VERIFY`      | Skips Vault TLS verification. For testing only                                      |
| `KEYSET_REWRAP_INTERVAL` | How often the keyset is wrapped again. Default 12h, at least 1h                     |
| `KEYSET_ROTATE_INTERVAL` | How old the data key may get before the core rotates it. Default 2160h, 0 turns it off |

`KMS_URI` takes one of:

- `hcvault://<host>/transit/keys/<key>` for HashiCorp Vault
- `scw-kms://regions/<region>/keys/<key-id>` for Scaleway

To move an existing install to a KMS, stop the core and run:

```bash
./nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku
```

Then set `KMS_URI` to the same value and start the core.

With a KMS nothing has to be rotated by hand. The core rotates the data key every `KEYSET_ROTATE_INTERVAL`, and wraps the keyset again every `KEYSET_REWRAP_INTERVAL`, which picks up a key rotation inside the KMS.

### Network

- **Terminate TLS in front of the core.** It listens with plain HTTP. `compose.prod.yml` runs Caddy for this.
- **Set `NOKKU_TRUSTED_PROXIES` to exactly your proxy.** The core only believes forwarded client-IP headers from these addresses. Too wide a range lets a client fake its address in the audit log and dodge rate limits.
- **Leave `NOKKU_ALLOW_PRIVATE_NETWORKS` off unless you need it.** Workspace owners choose SSO provider URLs and audit webhook destinations, so the core refuses to connect to private, loopback and link-local addresses. Set it to `true` only when every such address is trusted, like a self-hosted install with its identity provider or SIEM on an internal network. Never turn it on when you host for other people.

### File storage

Recordings are encrypted before they are stored, on local disk and on S3 alike.

If you set `NOKKU_S3_PUBLIC_URL` to serve avatars straight from the bucket, grant public read on the `avatars/` prefix only. Never make the whole bucket public. Recordings live under `videos/`.

### Database

- The core uses three roles. The owner (`PGUSER`) only runs migrations at start. Requests run as `nokku_app`, under row-level security. Work that spans workspaces, like the first start, billing webhooks and background jobs, runs as `nokku_system`, which bypasses it.
- Set `NOKKU_DB_APP_PASSWORD` to give the two runtime roles a password of their own instead of sharing the owner's.
- Use `PGSSLMODE=verify-full` when PostgreSQL is on another host.

### Releases

Releases are built with GoReleaser and come with checksums and signatures. Verify a download before you run it.

The container image is signed with cosign and carries an SPDX SBOM. Check an image before you deploy it:

```bash
cosign verify ghcr.io/nokku-sh/nokku:<version> \
  --certificate-identity https://github.com/nokku-sh/.github/.github/workflows/go-release.yaml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository nokku-sh/nokku
```

## What to know about the design

**The core is down, access is not.** Daemons enforce the access they last synced, and a certificate stays valid until it expires. Revoking access is immediate on servers that are in sync. A server that missed the sync is bounded by the certificate lifetime, so keep user certificates short.

**Session recordings.** Daemons stream recordings to the core, where they are encrypted at rest. Credential scrubbing runs after an upload completes and replaces the recording with a redacted copy. Between upload and scrub the stored recording is unredacted, though still encrypted. Scrubbing is best effort. A failed scrub is logged and the recording is kept as uploaded, and the matching is heuristic, so it cannot catch every secret.

**Row-level security is a safety net, not a wall.** Every tenant row belongs to one workspace, and a request only sees the rows of its own. The policy is the only workspace filter, queries name none. A connection with no workspace set sees nothing. This protects against application bugs. It does not protect against a compromised core: it holds the password of `nokku_system` too, and the workspace setting is an ordinary session variable. Queries are parameterized through sqlc, which is the defense against injection.

**Licensing.** A self-hosted core starts on the Community plan. License keys are Ed25519-signed and verified offline against a public key compiled into the binary. An expired key never stops the core. Licensed features turn off, and data beyond the Community limits is kept for 30 more days.
